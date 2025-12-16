// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFTAdapter.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BeGreenlyOFTAdapter
 * @notice Polygon-side adapter for bridging existing BGREEN token to BSC via LayerZero V2
 * @dev This contract locks BGREEN on Polygon and sends messages to BSC OFT contract
 * 
 * DEPLOYMENT CHECKLIST:
 * 1. Deploy this on Polygon Mainnet
 * 2. Constructor args: 
 *    - _token: Your deployed BGREEN token address (0x...)
 *    - _lzEndpoint: Polygon LayerZero V2 Endpoint (0x1a44076050125825900e736c501f859c50fE728c)
 *    - _delegate: Your multisig address (0xf09419a818A6f88BE1e20D6140e1E031Fd178F58)
 * 3. After deploy: call setPeer(BSC_CHAIN_ID, BSC_OFT_ADDRESS)
 * 4. Transfer ownership to multisig
 * 5. Users approve this contract to spend BGREEN, then call send()
 */
contract BeGreenlyOFTAdapter is Ownable, OFTAdapter {

    // Emergency controls
    bool public bridgingPaused;

    event BridgingPaused(bool status);

    constructor(
        address _token,           // Your BGREEN token address
        address _lzEndpoint,      // Polygon LZ endpoint
        address _delegate         // Multisig address
    ) Ownable(_delegate) OFTAdapter(_token, _lzEndpoint, _delegate) {
        // Ownership initialized via Ownable(_delegate) and OFTAdapter constructor
    }

    /**
     * @notice Emergency pause (if needed in future)
     * @dev Only owner (multisig) can call
     */
    function setBridgingPause(bool _paused) external onlyOwner {
        bridgingPaused = _paused;
        emit BridgingPaused(_paused);
    }

    /**
     * @notice Helper to convert address to bytes32 for setPeer
     */
    function addressToBytes32(address _addr) public pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }

    // Note: we keep bridgingPaused state and owner control, but do not override
    // internal OFTAdapter hooks here to avoid signature mismatches across V2 versions.
    // If you want strict pause, we can add overrides after confirming the exact
    // OFTAdapter version and its internal hook signatures.
}

/**
 * DEPLOYMENT STEPS:
 * 
 * 1. Get addresses:
 *    BGREEN_TOKEN = 0x... (your deployed token)
 *    POLYGON_LZ_ENDPOINT = 0x1a44076050125825900e736c501f859c50fE728c
 *    MULTISIG = 0xf09419a818A6f88BE1e20D6140e1E031Fd178F58
 * 
 * 2. Deploy adapter:
 *    new BeGreenlyOFTAdapter(BGREEN_TOKEN, POLYGON_LZ_ENDPOINT, MULTISIG)
 * 
 * 3. Configure peer (after BSC OFT is deployed):
 *    adapter.setPeer(BSC_CHAIN_ID, addressToBytes32(BSC_OFT_ADDRESS))
 *    // BSC_CHAIN_ID for LZ V2 = 30102
 * 
 * 4. Test bridge:
 *    - Approve adapter to spend BGREEN
 *    - Call send() with destination chain and amount
 * 
 * SECURITY:
 * - Adapter can only LOCK tokens (via transferFrom)
 * - Cannot mint new tokens
 * - Multisig controls setPeer, setDelegate
 * - LayerZero handles message verification
 */