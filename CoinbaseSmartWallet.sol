// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount} from "./IAccount.sol";
import {UserOperation, UserOperationLib} from "./UserOperation.sol";
import {Receiver} from "./Receiver.sol";
import {SignatureCheckerLib} from "./SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "./UUPSUpgradeable.sol";
import {WebAuthn} from "./WebAuthn.sol";

import {ERC1271} from "./ERC1271.sol";
import {MultiOwnable} from "./MultiOwnable.sol";

/// @title Coinbase Smart Wallet (Upgraded Version)
///
/// @notice This upgraded version of the Coinbase Smart Wallet:
///         - Compiles with Solidity 0.8.28
///         - Adds a `batchTransferBBW` function to call BBW’s `batchTransfer` method in a manner compatible
///           with ERC-4337 gas sponsorship. This assumes a paymaster might pay for gas, so no direct changes
///           are needed except ensuring we do not revert when paymasters are present.
///         - Maintains storage layout consistency (no new storage variables added before existing ones).
///         - Uses the existing `validateUserOp` logic but ensures it does not revert when a paymaster is used.
///           If a paymaster is present in `userOp.paymasterAndData`, we simply proceed as normal. The paymaster
///           will handle gas reimbursement.
///
contract CoinbaseSmartWallet is ERC1271, IAccount, MultiOwnable, UUPSUpgradeable, Receiver {
    /// @notice A wrapper struct used for signature validation so that callers
    ///         can identify the owner that signed.
    struct SignatureWrapper {
        /// @dev The index of the owner that signed, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `MultiOwnable.ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        ///      If `MultiOwnable.ownerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
        bytes signatureData;
    }

    /// @notice Represents a call to make.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    /// @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable
    ///         transactions.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @notice Thrown when `initialize` is called but the account already has had at least one owner.
    error Initialized();

    /// @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
    ///         `canSkipChainIdValidation`
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown in validateUserOp if the key of `UserOperation.nonce` does not match the calldata.
    error InvalidNonceKey(uint256 key);

    /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint, the owner, nor the account itself.
    modifier onlyEntryPointOrOwner() virtual {
        if (msg.sender != entryPoint()) {
            _checkOwner();
        }
        _;
    }

    /// @notice Sends to the EntryPoint the missing funds for this transaction if needed.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;
        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    constructor() {
        // Implementation should not be initializable (does not affect proxies which use their own storage).
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        _initializeOwners(owners);
    }

    /// @notice Initializes the account with the `owners`.
    ///
    /// @dev Reverts if the account has had at least one owner, i.e. has been initialized.
    ///
    /// @param owners Array of initial owners for this account.
    function initialize(bytes[] calldata owners) external payable virtual {
        if (nextOwnerIndex() != 0) {
            revert Initialized();
        }

        _initializeOwners(owners);
    }

    /// @inheritdoc IAccount
    ///
    /// @notice This method now is paymaster-compatible: If `paymasterAndData` is not empty, we do not revert.
    ///         We simply proceed with the signature check. If signature is valid, return success (0), else (1).
    ///         If signature is valid, `paymasterAndData` ensures the EntryPoint can handle gas with the paymaster.
    ///         No aggregator is used, so we return 0 or 1.
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        uint256 key = userOp.nonce >> 64;

        if (bytes4(userOp.callData) == this.executeWithoutChainIdValidation.selector) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        }

        // Return 0 if the recovered address matches the owner, else 1 for signature failure.
        if (_isValidSignature(userOpHash, userOp.signature)) {
            return 0;
        }

        return 1;
    }

    /// @notice Executes `calls` on this account (i.e. self call).
    ///
    /// @dev Can only be called by the Entrypoint.
    /// @dev Reverts if a call is not allowed to skip chain ID validation.
    function executeWithoutChainIdValidation(bytes[] calldata calls) external payable virtual onlyEntryPoint {
        for (uint256 i; i < calls.length; i++) {
            bytes calldata call = calls[i];
            bytes4 selector = bytes4(call);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }
            _call(address(this), 0, call);
        }
    }

    /// @notice Executes a call from this account.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        virtual
        onlyEntryPointOrOwner
    {
        _call(target, value, data);
    }

    /// @notice Executes a batch of calls from this account.
    ///
    /// @dev Can only be called by the Entrypoint or an owner.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrOwner {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice Calls BBW’s batchTransfer function, compatible with paymaster sponsorship.
    /// @dev Ensure this contract is set as the `authorizedSmartWallet` in the BBW contract.
    /// @dev Can only be called by the Entrypoint or an owner (including itself).
    /// @param bbw The BBW contract address.
    /// @param recipients The recipients array.
    /// @param amounts The amounts array.
    function batchTransferBBW(address bbw, address[] calldata recipients, uint256[] calldata amounts)
        external
        onlyEntryPointOrOwner
    {
        // Calls BBW.batchTransfer(recipients, amounts)
        _call(bbw, 0, abi.encodeWithSelector(bytes4(keccak256("batchTransfer(address[],uint256[])")), recipients, amounts));
    }

    /// @notice Returns the address of the EntryPoint v0.6.
    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    /// @notice Computes the hash of the `UserOperation` in the same way as EntryPoint v0.6, but leaves out the chain ID.
    function getUserOpHashWithoutChainId(UserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    /// @notice Returns the implementation of the ERC1967 proxy.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Returns whether `functionSelector` can be called in `executeWithoutChainIdValidation`.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiOwnable.addOwnerPublicKey.selector
                || functionSelector == MultiOwnable.addOwnerAddress.selector
                || functionSelector == MultiOwnable.removeOwnerAtIndex.selector
                || functionSelector == MultiOwnable.removeLastOwner.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }

    /// @dev Internal call helper that reverts if the call fails.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @inheritdoc ERC1271
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);

        if (ownerBytes.length == 32) {
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(ownerBytes);
            }

            address owner;
            assembly ("memory-safe") {
                owner := mload(add(ownerBytes, 32))
            }

            return SignatureCheckerLib.isValidSignatureNow(owner, hash, sigWrapper.signatureData);
        }

        if (ownerBytes.length == 64) {
            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));
            WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth));
            return WebAuthn.verify({challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: x, y: y});
        }

        revert InvalidOwnerBytesLength(ownerBytes);
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Coinbase Smart Wallet", "1");
    }
}
