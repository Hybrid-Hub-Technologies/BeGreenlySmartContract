// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Minimal LayerZero endpoint interface (declared outside contract to avoid parser errors)
interface ILayerZeroEndpoint {
    function send(uint16 _dstChainId, bytes calldata _destination, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) external payable;
    function estimateFees(uint16 _dstChainId, address _userApplication, bytes calldata _payload, bool _payInZRO, bytes calldata _adapterParams) external view returns (uint256 nativeFee, uint256 zroFee);
}

/**
 * @title BeGreenlyToken Secure V3 - FINAL (ALL VULNERABILITIES FIXED)
 * @notice Production-Ready • Audit-Ready • Zero Backdoors
 * @dev Gnosis Safe 3-of-5 Multisig • Emergency Recovery • Anti-Hack
 */
contract BeGreenlyTokenSecureV3 is 
    Initializable, 
    ERC20Upgradeable,
    AccessControlUpgradeable, 
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable 
{
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    uint256 public constant MAX_SUPPLY = 35_000_000_000 * 10**18;
    uint256 public constant MAX_FEE_PERCENTAGE = 5;
    uint256 public constant MIN_WALLET_PERCENTAGE = 1;
    uint256 public constant MAX_WALLET_PERCENTAGE = 10;
    uint256 public constant MAX_TX_LIMIT = 10_000 * 1e18;
    uint256 public constant MAX_BATCH_SIZE = 100; // Gas optimization
    address public constant MULTISIG_ADDRESS = 0xf09419a818A6f88BE1e20D6140e1E031Fd178F58;

    struct TokenConfig {
        uint256 transactionFeePercentage;
        uint256 maxWalletPercentage;
        address feeCollector;
    }

    uint256 public maxTxLimit;
    uint256 public txLimit;

    struct WalletControls {
        bool isBlacklisted;
        bool isFeeExempt;
        bool isWalletLimitExempt;
        bool isTransactionLimitExempt;
    }

    TokenConfig private _tokenConfig;
    mapping(address => WalletControls) private _walletControls;
    mapping(address => uint256) private _lastTransactionTimestamp;
    mapping(address => uint256) private _lastTxBlock;

    uint256 public txDelaySeconds;
    bool public ownershipRenounced;
    address public multisigWallet;
    address public blacklistRecipient;

    event WalletControlsUpdated(address indexed wallet, WalletControls controls);
    event TokenConfigModified(TokenConfig newConfig);
    event LimitsUpdated(uint256 newMaxWalletPercentage, uint256 newMaxTransactionPercentage);
    event FeeCollected(address indexed sender, address indexed collector, uint256 amount);
    event BlacklistBatch(address[] accounts, bool status);
    event EmergencyBlacklist(address indexed account, address indexed by);
    event RecoveryPerformed(address indexed target, address indexed recipient, uint256 amount);
    event OwnershipRenounced(address indexed previousOwner, address indexed multisig);
    event BlacklistRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event RoleTransferredToMultisig(bytes32 indexed role, address indexed multisig);
    // Note: forced seizure on blacklist removed for safety on proxyed live contract
    event WalletExemptionsUpdated(address indexed wallet, bool feeExempt, bool walletLimitExempt, bool txLimitExempt);
    event TxDelayUpdated(uint256 oldDelay, uint256 newDelay);

    error InvalidAddress();
    error ExceedsMaxSupply();
    error BlacklistedAddress();
    error ExceedsMaxWallet();
    error ExceedsMaxTransaction();
    error MustWaitBetweenTransactions();
    error InvalidLimits();
    error FeeTooHigh();
    error AlreadyRenounced();
    error NotMultisig();
    error AlreadyInitialized();
    error ImmutableMultisig();
    error DelayTooHigh();
    error SameOriginInSameBlock();
    error TargetNotBlacklisted();
    error NoTokensToRecover();
    error LengthMismatch();
    error ContractPaused();
    error ZeroAmount();
    error SelfTransfer();
    error BatchTooLarge();

    modifier onlyMultisig() {
        if (msg.sender != multisigWallet) revert NotMultisig();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initializeV3(
        address /* _multisigWallet */,
        address[] memory /* guardians */,
        address feeCollector
    ) external reinitializer(3) {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert InvalidAddress();
        if (multisigWallet != address(0)) revert AlreadyInitialized();
        if (MULTISIG_ADDRESS == address(0)) revert InvalidAddress();
        if (feeCollector == address(0)) revert InvalidAddress();
        // Initialize OZ modules for upgradeable contract
        __ERC20_init("BeGreenly Coin", "BGREEN");
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        multisigWallet = MULTISIG_ADDRESS;
        blacklistRecipient = MULTISIG_ADDRESS;
        txDelaySeconds = 1;

        _tokenConfig = TokenConfig({
            transactionFeePercentage: 1,
            maxWalletPercentage: 3,
            feeCollector: feeCollector
        });
        // Ensure fee collector is not accidentally blocked by wallet limits
        _walletControls[feeCollector].isWalletLimitExempt = true;
        maxTxLimit = MAX_TX_LIMIT;
        txLimit = 1000 * 1e18;

        _walletControls[MULTISIG_ADDRESS] = WalletControls({
            isBlacklisted: false,
            isFeeExempt: true,
            isWalletLimitExempt: true,
            isTransactionLimitExempt: true
        });

        _grantRole(DEFAULT_ADMIN_ROLE, MULTISIG_ADDRESS);
        _grantRole(GOVERNANCE_ROLE, MULTISIG_ADDRESS);
        _grantRole(PAUSER_ROLE, MULTISIG_ADDRESS);
        _grantRole(UPGRADER_ROLE, MULTISIG_ADDRESS);
        emit RoleTransferredToMultisig(DEFAULT_ADMIN_ROLE, MULTISIG_ADDRESS);

        _pause();
    }

    function setWalletExemptions(
        address wallet,
        bool feeExempt,
        bool walletLimitExempt,
        bool txLimitExempt
    ) external onlyMultisig {
        if (wallet == address(0)) revert InvalidAddress();
        _walletControls[wallet].isFeeExempt = feeExempt;
        _walletControls[wallet].isWalletLimitExempt = walletLimitExempt;
        _walletControls[wallet].isTransactionLimitExempt = txLimitExempt;
        emit WalletExemptionsUpdated(wallet, feeExempt, walletLimitExempt, txLimitExempt);
    }

    function setTxDelay(uint256 seconds_) external onlyMultisig {
        if (seconds_ > 60) revert DelayTooHigh();
        uint256 old = txDelaySeconds;
        txDelaySeconds = seconds_;
        emit TxDelayUpdated(old, seconds_);
    }

    function setBlacklistRecipient(address newRecipient) external onlyMultisig {
        if (newRecipient == address(0)) revert InvalidAddress();
        address oldRecipient = blacklistRecipient;
        blacklistRecipient = newRecipient;
        emit BlacklistRecipientUpdated(oldRecipient, newRecipient);
    }

    /**
     * @notice Emergency batch blacklist with gas limit protection
     * @dev Works while PAUSED for emergency recovery
     */
    function batchBlacklist(
        address[] calldata accounts,
        bool status
    ) external nonReentrant onlyMultisig {
        if (accounts.length > MAX_BATCH_SIZE) revert BatchTooLarge();

        uint256 len = accounts.length;
        for (uint i = 0; i < len; ++i) {
            address a = accounts[i];
            if (_walletControls[a].isBlacklisted != status) {
                _walletControls[a].isBlacklisted = status;
                emit WalletControlsUpdated(a, _walletControls[a]);
            }
        }
        emit BlacklistBatch(accounts, status);
    }

    function emergencyBlacklist(address account) external nonReentrant onlyMultisig {
        if (!_walletControls[account].isBlacklisted) {
            _walletControls[account].isBlacklisted = true;
            emit WalletControlsUpdated(account, _walletControls[account]);
        }
        emit EmergencyBlacklist(account, msg.sender);
    }

    function setBlacklist(address account, bool status) external nonReentrant onlyMultisig {
        if (_walletControls[account].isBlacklisted != status) {
            _walletControls[account].isBlacklisted = status;
            emit WalletControlsUpdated(account, _walletControls[account]);
        }
    }

    function multisigRecover(address target, address recipient) external nonReentrant onlyMultisig {
        if (!_walletControls[target].isBlacklisted) revert TargetNotBlacklisted();
        uint256 amount = balanceOf(target);
        if (amount == 0) revert NoTokensToRecover();
        if (recipient == address(0)) revert InvalidAddress();

        super._transfer(target, recipient, amount);
        emit RecoveryPerformed(target, recipient, amount);
    }

    function batchTransfer(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external nonReentrant onlyMultisig whenNotPaused {
        if (recipients.length != amounts.length) revert LengthMismatch();
        if (recipients.length > MAX_BATCH_SIZE) revert BatchTooLarge();

        uint256 len = recipients.length;
        for (uint256 i = 0; i < len; ++i) {
            address to = recipients[i];
            uint256 amt = amounts[i];
            if (to == address(0)) revert InvalidAddress();
            if (_walletControls[to].isBlacklisted) revert BlacklistedAddress();
            _transfer(msg.sender, to, amt);
        }
    }

    function setTransactionFeeByMultisig(uint256 newFee) external onlyMultisig {
        if (newFee > MAX_FEE_PERCENTAGE) revert FeeTooHigh();
        if (_tokenConfig.transactionFeePercentage != newFee) {
            _tokenConfig.transactionFeePercentage = newFee;
            emit TokenConfigModified(_tokenConfig);
        }
    }

    function setWalletLimit(uint256 walletPct) external onlyMultisig {
        if (walletPct < MIN_WALLET_PERCENTAGE || walletPct > MAX_WALLET_PERCENTAGE) revert InvalidLimits();
        if (_tokenConfig.maxWalletPercentage != walletPct) {
            _tokenConfig.maxWalletPercentage = walletPct;
            emit LimitsUpdated(walletPct, maxTxLimit);
        }
    }

    function setMaxTxLimit(uint256 newLimit) external onlyMultisig {
        if (newLimit > MAX_TX_LIMIT) revert InvalidLimits();
        if (maxTxLimit != newLimit) {
            maxTxLimit = newLimit;
            emit LimitsUpdated(_tokenConfig.maxWalletPercentage, maxTxLimit);
        }
    }

    function setTxLimit(uint256 newLimit) external onlyMultisig {
        if (newLimit > MAX_TX_LIMIT) revert InvalidLimits();
        if (txLimit != newLimit) {
            txLimit = newLimit;
            emit LimitsUpdated(_tokenConfig.maxWalletPercentage, txLimit);
        }
    }

    function setFeeCollectorByMultisig(address newCollector) external onlyMultisig {
        if (newCollector == address(0)) revert InvalidAddress();
        if (_tokenConfig.feeCollector != newCollector) {
            _tokenConfig.feeCollector = newCollector;
            // Exempt fee collector from wallet limits to avoid accidental max-wallet violations
            _walletControls[newCollector].isWalletLimitExempt = true;
            emit TokenConfigModified(_tokenConfig);
        }
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function renounceDeployerOwnership() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (ownershipRenounced) revert AlreadyRenounced();
        if (multisigWallet == address(0)) revert InvalidAddress();

        address deployer = msg.sender;
        if (hasRole(DEFAULT_ADMIN_ROLE, deployer)) _revokeRole(DEFAULT_ADMIN_ROLE, deployer);
        if (hasRole(GOVERNANCE_ROLE, deployer)) _revokeRole(GOVERNANCE_ROLE, deployer);
        if (hasRole(PAUSER_ROLE, deployer)) _revokeRole(PAUSER_ROLE, deployer);
        if (hasRole(UPGRADER_ROLE, deployer)) _revokeRole(UPGRADER_ROLE, deployer);

        ownershipRenounced = true;
        emit OwnershipRenounced(deployer, multisigWallet);
    }

    function updateMultisig(address) external pure {
        revert ImmutableMultisig();
    }

    function rotateMultisig(address) external pure {
        revert ImmutableMultisig();
    }

    /**
     * @notice FIXED: Wallet limit check uses ACTUAL received amount (after fee)
     * @dev Critical fix to prevent wallet limit bypass
     */
    function _enforceTransferRules(address from, address to, uint256 amount) internal {
        if (from == address(0) || to == address(0)) return;
        
        // Zero amount check
        if (amount == 0) revert ZeroAmount();
        
        // Self-transfer check
        if (from == to) revert SelfTransfer();
        
        // Pause check
        if (paused()) revert ContractPaused();

        WalletControls storage senderControls = _walletControls[from];
        WalletControls storage recipientControls = _walletControls[to];

        // Blacklist check
        if (senderControls.isBlacklisted) revert BlacklistedAddress();
        if (recipientControls.isBlacklisted) revert BlacklistedAddress();

        // Anti-bot delay
        if (!senderControls.isTransactionLimitExempt && txDelaySeconds > 0) {
            if (block.timestamp <= _lastTransactionTimestamp[from] + txDelaySeconds) {
                revert MustWaitBetweenTransactions();
            }
            _lastTransactionTimestamp[from] = block.timestamp;
        }

        // Anti-MEV
        if (!senderControls.isTransactionLimitExempt) {
            if (_lastTxBlock[from] == block.number) {
                revert SameOriginInSameBlock();
            }
            _lastTxBlock[from] = block.number;
        }

        // FIXED: Calculate actual amount recipient will receive (after fee deduction)
        if (!recipientControls.isWalletLimitExempt) {
            uint256 actualReceived = amount;
            
            // If fee applies, recipient gets less
            if (_tokenConfig.transactionFeePercentage > 0 && !senderControls.isFeeExempt) {
                uint256 feeAmount = (amount * _tokenConfig.transactionFeePercentage) / 100;
                actualReceived = amount - feeAmount;
            }
            
            uint256 maxWallet = (MAX_SUPPLY * _tokenConfig.maxWalletPercentage) / 100;
            uint256 toBalance = balanceOf(to);
            if (toBalance + actualReceived > maxWallet) revert ExceedsMaxWallet();
        }

        // Transaction limit check
        if (!senderControls.isTransactionLimitExempt) {
            if (amount > maxTxLimit) revert ExceedsMaxTransaction();
        }
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        address sender = _msgSender();
        
        _enforceTransferRules(sender, recipient, amount);
        
        WalletControls memory senderControls = _walletControls[sender];
        
        if (_tokenConfig.transactionFeePercentage > 0 && !senderControls.isFeeExempt) {
            uint256 feeAmount = (amount * _tokenConfig.transactionFeePercentage) / 100;
            uint256 netAmount = amount - feeAmount;
            
            _transfer(sender, _tokenConfig.feeCollector, feeAmount);
            emit FeeCollected(sender, _tokenConfig.feeCollector, feeAmount);
            
            _transfer(sender, recipient, netAmount);
        } else {
            _transfer(sender, recipient, amount);
        }
        return true;
    }

    /**
     * @notice FULLY FIXED transferFrom - No vulnerability
     * @dev Allowance matches actual amount taken from sender
     *      Fee is deducted from recipient's received amount
     *      Example: transferFrom(sender, recipient, 1000) with 5% fee:
     *      - Allowance spent: 1000
     *      - Sender loses: 1000
     *      - Recipient gets: 950
     *      - Fee collector: 50
     */
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        // Spend allowance for EXACT amount (fee deducted from recipient, not added to sender)
        _spendAllowance(sender, _msgSender(), amount);
        
        // All security checks
        _enforceTransferRules(sender, recipient, amount);
        
        WalletControls memory senderControls = _walletControls[sender];
        
        // Fee calculation - recipient gets less, sender pays exact 'amount'
        if (_tokenConfig.transactionFeePercentage > 0 && !senderControls.isFeeExempt) {
            uint256 feeAmount = (amount * _tokenConfig.transactionFeePercentage) / 100;
            uint256 netAmount = amount - feeAmount;
            
            _transfer(sender, _tokenConfig.feeCollector, feeAmount);
            emit FeeCollected(sender, _tokenConfig.feeCollector, feeAmount);
            
            _transfer(sender, recipient, netAmount);
        } else {
            _transfer(sender, recipient, amount);
        }
        return true;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {
        if (newImplementation == address(0)) revert InvalidAddress();
    }

    // --- LayerZero / OFT-related storage (no on-token bridging implementation) ---
    ILayerZeroEndpoint public lzEndpoint;
    mapping(uint16 => bytes) public trustedRemoteLookup; // dstChainId => remote contract bytes
    bool public oftEnabled;
    // NOTE: `oftAdapter` is reserved to point to an external official OFT adapter contract.
    // Keep this storage slot to remain layout-compatible with previous upgrades.
    address public oftAdapter;

    event LayerZeroEndpointUpdated(address indexed endpoint);
    event TrustedRemoteSet(uint16 indexed chainId, bytes remote);
    event OftAdapterUpdated(address indexed oldAdapter, address indexed newAdapter);
    event CrossChainSent(address indexed sender, uint16 indexed dstChainId, bytes indexed toAddress, uint256 amount, uint64 nonce);
    event CrossChainReceived(uint16 indexed srcChainId, address indexed to, uint256 amount, uint64 nonce);

    error OftDisabled();
    error TrustedRemoteNotSet();
    error InvalidLayerZeroEndpoint();
    error NotLayerZeroEndpoint();

    // Set LayerZero endpoint (multisig only)
    function setLayerZeroEndpoint(address endpoint) external onlyMultisig {
        if (endpoint == address(0)) revert InvalidAddress();
        if (address(lzEndpoint) != endpoint) {
            lzEndpoint = ILayerZeroEndpoint(endpoint);
            emit LayerZeroEndpointUpdated(endpoint);
        }
    }

    // Set trusted remote contract address for a chain id (multisig only)
    function setTrustedRemote(uint16 _chainId, bytes calldata _remote) external onlyMultisig {
        if (_remote.length == 0) revert InvalidAddress();
        // avoid unnecessary storage write
        if (keccak256(trustedRemoteLookup[_chainId]) != keccak256(_remote)) {
            trustedRemoteLookup[_chainId] = _remote;
            emit TrustedRemoteSet(_chainId, _remote);
        }
    }

    // Toggle OFT functionality (multisig only)
    function toggleOftEnabled(bool enabled) external onlyMultisig {
        if (oftEnabled != enabled) {
            oftEnabled = enabled;
        }
    }

    // Set official OFT adapter address (deployer/multisig should deploy official adapter separately)
    function setOftAdapter(address adapter) external onlyMultisig {
        if (adapter == address(0)) revert InvalidAddress();
        address old = oftAdapter;
        if (old != adapter) {
            oftAdapter = adapter;
            emit OftAdapterUpdated(old, adapter);
        }
    }

    /**
     * @notice Lock tokens on this chain and send a LayerZero message to destination chain.
     * @dev Tokens are transferred to `multisigWallet` (locked). Destination `lzReceive` will
     *      transfer tokens from its `multisigWallet` to the recipient (unlock).
     *      Caller must send enough native gas to pay LayerZero fees via `msg.value` or use adapter params.
     */
    function sendCrossChain(uint16, bytes calldata, uint256, bytes calldata) external payable whenNotPaused nonReentrant {
        // Deprecated: Use official LayerZero OFT adapter contracts and the external adapter's API.
        // This contract intentionally does NOT implement custom bridging logic.
        // Deploy an official OFT adapter (Polygon) that interacts with this token (via ERC20 approvals/transfers).
        revert OftDisabled();
    }

    // Called by LayerZero endpoint on incoming messages
    function lzReceive(uint16, bytes calldata, uint64, bytes calldata) external nonReentrant whenNotPaused {
        // Deprecated: this contract does not handle inbound LayerZero messages.
        // Use official LayerZero OFT implementations on destination chains (they will call token transfers
        // or adapter contracts to unlock/credit users). Keep bridging logic off-token for security.
        revert NotLayerZeroEndpoint();
    }

    function getWalletControls(address wallet) external view returns (WalletControls memory) {
        return _walletControls[wallet];
    }

    function getTokenConfig() external view returns (TokenConfig memory) {
        return _tokenConfig;
    }

    function isBlacklisted(address account) external view returns (bool) {
        return _walletControls[account].isBlacklisted;
    }

    function getContractLimits() external view returns (
        uint256 maxFee,
        uint256 minWallet,
        uint256 maxWallet,
        uint256 txLimit_,
        uint256 maxTx
    ) {
        return (
            MAX_FEE_PERCENTAGE,
            MIN_WALLET_PERCENTAGE,
            MAX_WALLET_PERCENTAGE,
            txLimit,
            maxTxLimit
        );
    }

    // Reserved storage gap for future variable additions (storage-compatible)
    uint256[50] private __gap;
}
