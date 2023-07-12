// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./ERC1400.sol";
import "./ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title PPT
 * @dev This contract extends the ERC1400 contract with additional functionality
 * to charge transfer fees that are sent to specific addresses.
 */
contract PPT is ERC1400 {
    using SafeMath for uint256;

    address public feeAddr; // Address to receive the 0.3% transaction fee
    address public prosynergyAddr; // Address to receive the 0.125% transaction fee
    mapping(address => bool) public whitelist;
    mapping(address => uint256) public nonces; // KYC nonce
    address public publicKey;


    constructor(
        address _owner,
        address _to,
        address _feeAddr,
        address _prosynergyAddr,
        address _publicKey
    ) ERC1400("Pawpoints", "PPT", 1) {
        require(_feeAddr != address(0));
        require(_prosynergyAddr != address(0));
        if (_owner != msg.sender) transferOwnership(_owner);
        publicKey = _publicKey;
        feeAddr = _feeAddr;
        whitelist[_to] = true;
        _issueByPartition(
            _defaultPartition,
            msg.sender,
            _to,
            1_000_000_000 * 1e18,
            ""
        );
        _isIssuable = false;
        prosynergyAddr = _prosynergyAddr;
    }

    /**
     * @dev Updates the fee addresses.
     * Can only be called by the contract owner.
     */
    function upgradeFeeAddr(
        address _feeAddr,
        address _prosynergyAddr
    ) public onlyOwner {
        require(_feeAddr != address(0));
        require(_prosynergyAddr != address(0));
        feeAddr = _feeAddr;
        prosynergyAddr = _prosynergyAddr;
    }

    function setPublicKey(address _publicKey) public onlyOwner {
        publicKey = _publicKey;
    }

    /**
     * @notice Sets the whitelist status for an address
     * @param _addr The address to set the whitelist status for
     * @param _state Whether the address should be whitelisted or not
     * @dev Can only be called by the contract owner
     */
    function setWhitelist(address _addr, bool _state) public onlyOwner {
        whitelist[_addr] = _state;
    }

    /**
     * @dev Executes a transfer by partition and charges transfer fees.
     */
    function _transferByPartition(
        bytes32 fromPartition,
        address operator,
        address from,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory operatorData
    ) internal override returns (bytes32) {
        if (_checkWhiteList(from, to))
            return
                super._transferByPartition(
                    fromPartition,
                    operator,
                    from,
                    to,
                    value,
                    data,
                    operatorData
                );
        
        // KYC check
        if(data.length != 0) {
            (bool result, uint256 nonce) = validateData(from, to, value, data);
            require(result, "data is not valid");
            require(nonces[from] == nonce, "nonce claimed");
            
            nonces[from] = nonce + 1;
            return
                super._transferByPartition(
                    fromPartition,
                    operator,
                    from,
                    to,
                    value,
                    data,
                    operatorData
                );
        }

        require(_balanceOfByPartition[from][fromPartition] >= value, "52"); // 0x52 insufficient balance

        bytes32 toPartition = fromPartition;
        if (operatorData.length != 0 && data.length >= 64) {
            toPartition = _getDestinationPartition(fromPartition, data);
        }

        if (toPartition != fromPartition) {
            emit ChangedPartition(fromPartition, toPartition, value);
        }

        uint256 feeAmount = value.mul(300).div(100000); // 0.3%
        uint256 prosynergyAmount = value.mul(125).div(100000); // 0.125%

        _removeTokenFromPartition(from, fromPartition, value);
        value = value.sub(feeAmount).sub(prosynergyAmount);

        _transferWithData(from, to, value);
        _addTokenToPartition(to, toPartition, value);
        emit TransferByPartition(
            fromPartition,
            operator,
            from,
            to,
            value,
            data,
            operatorData
        );

        //transfer fee
        if (feeAmount > 0) {
            _transferWithData(from, feeAddr, feeAmount);
            _addTokenToPartition(feeAddr, toPartition, feeAmount);
            emit TransferByPartition(
                fromPartition,
                operator,
                from,
                feeAddr,
                feeAmount,
                data,
                operatorData
            );
        }

        //prosynergy fee
        if (prosynergyAmount > 0) {
            _transferWithData(from, prosynergyAddr, prosynergyAmount);
            _addTokenToPartition(prosynergyAddr, toPartition, prosynergyAmount);
            emit TransferByPartition(
                fromPartition,
                operator,
                from,
                prosynergyAddr,
                prosynergyAmount,
                data,
                operatorData
            );
        }
        return toPartition;
    }

    /**
     * @dev Returns true if the `from` or `to` address is in the whitelist.
     */
    function _checkWhiteList(
        address from,
        address to
    ) internal view returns (bool) {
        if (from == to) return true;
        if (from == owner()) return true;
        if (to == owner()) return true;
        return whitelist[to] || whitelist[from];
    }

    function validateData(
        address from,
        address to,
        uint256 value,
        bytes memory data
    ) public view returns (bool, uint256) {
        (uint256 nonce, bytes memory signature) = abi.decode(data, (uint256, bytes));
        bool result = verify(getMessageHash(from, to, value, nonce), signature);
        return (result, nonce);
    }

    function verify(bytes32 messageHash, bytes memory signature) public view returns(bool) {
        return publicKey == ECDSA.recover(messageHash, signature);
    }

    function getMessageHash(address from, address to, uint256 value, uint256 nonce) public view returns(bytes32) {
        return ECDSA.toEthSignedMessageHash(keccak256(abi.encodePacked(from, to, value, block.chainid, nonce)));
    }
    
    function _issueByPartition(
        bytes32 toPartition,
        address operator,
        address to,
        uint256 value,
        bytes memory data
    ) internal override {
        require(_totalSupply == 0);
        super._issueByPartition(
            toPartition,
            operator,
            to,
            value,
            data
        );
    }
}
