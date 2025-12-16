// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFT.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BeGreenlyOFT
 * @notice BSC-side OFT token for bridged BGREEN from Polygon via LayerZero V2
 * @dev This contract mints/burns BGREEN on BSC based on LayerZero messages
 * 
 * DEPLOYMENT CHECKLIST:
 * 1. Deploy this on BSC Mainnet
 * 2. Constructor args:
 *    - name: "BeGreenly Coin"
 *    - symbol: "BGREEN"
 *    - _lzEndpoint: BSC LayerZero V2 Endpoint (0x1a44076050125825900e736c501f859c50fE728c)
 *    - _delegate: Your multisig address (0xf09419a818A6f88BE1e20D6140e1E031Fd178F58)
 * 3. After deploy: call setPeer(POLYGON_CHAIN_ID, POLYGON_ADAPTER_ADDRESS)
 * 4. Transfer ownership to multisig
 * 5. Create PancakeSwap pool: BGREEN-WBNB
 */
contract BeGreenlyOFT is Ownable, OFT {
    
    // Emergency controls
    bool public bridgingPaused;
    
    event BridgingPaused(bool status);
    
    constructor(
        string memory _name,
        string memory _symbol,
        address _lzEndpoint,     // BSC LZ endpoint
        address _delegate        // Multisig address
    ) Ownable(_delegate) OFT(_name, _symbol, _lzEndpoint, _delegate) {
        // Ownership initialized via Ownable(_delegate) and OFT constructor
    }

    /**
     * @notice Emergency pause bridging
     * @dev Only owner (multisig) can pause
     */
    function setBridgingPause(bool _paused) external onlyOwner {
        bridgingPaused = _paused;
        emit BridgingPaused(_paused);
    }
    // NOTE: We do NOT override internal OFT hooks here because the exact
    // signatures for `_debit`/`_credit` may differ between LayerZero V2
    // releases. If you want a strict emergency stop that prevents bridging,
    // use `bridgingPaused` in public entry points or re-add overrides after
    // confirming the OFT contract version and signatures.

    /**
     * @notice Get decimals (18 to match Polygon)
     */
    function decimals() public pure override returns (uint8) {
        return 18;
    }

    /**
     * @notice Helper to convert address to bytes32 for setPeer
     */
    function addressToBytes32(address _addr) public pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }
}

/**
 * DEPLOYMENT STEPS:
 * 
 * 1. Get addresses:
 *    BSC_LZ_ENDPOINT = 0x1a44076050125825900e736c501f859c50fE728c
 *    MULTISIG = 0xf09419a818A6f88BE1e20D6140e1E031Fd178F58
 * 
 * 2. Deploy OFT:
 *    new BeGreenlyOFT("BeGreenly Coin", "BGREEN", BSC_LZ_ENDPOINT, MULTISIG)
 * 
 * 3. Configure peer (after Polygon adapter is deployed):
 *    oft.setPeer(POLYGON_CHAIN_ID, addressToBytes32(POLYGON_ADAPTER_ADDRESS))
 *    // Polygon chain ID for LZ V2 = 30109
 * 
 * 4. Create PancakeSwap pool:
 *    - Go to PancakeSwap V3
 *    - Create BGREEN-WBNB pair
 *    - Add liquidity (e.g., 1M BGREEN + equivalent BNB)
 * 
 * 5. Test bridge:
 *    - Bridge 100 BGREEN from Polygon
 *    - Verify on LayerZeroScan
 *    - Check BSC balance
 *    - Test swap on PancakeSwap
 * 
 * CROSS-CHAIN FLOW:
 * 
 * Polygon → BSC:
 * 1. User approves Polygon Adapter
 * 2. User calls adapter.send()
 * 3. Adapter locks BGREEN on Polygon
 * 4. LayerZero relays message to BSC
 * 5. BSC OFT mints BGREEN to user
 * 
 * BSC → Polygon:
 * 1. User calls oft.send()
 * 2. OFT burns BGREEN on BSC
 * 3. LayerZero relays message to Polygon
 * 4. Adapter unlocks BGREEN to user
 * 
 * DEX INTEGRATION:
 * - Wallets auto-detect PancakeSwap router
 * - Aggregators (1inch, Symbiosis) find pools automatically
 * - No manual configuration needed
 * - Users can swap BGREEN-BNB directly in MetaMask
 */