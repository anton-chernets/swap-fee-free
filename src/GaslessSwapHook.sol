// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {BalanceDeltaLibrary, BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import { BeforeSwapDelta, BeforeSwapDeltaLibrary } from "v4-core/types/BeforeSwapDelta.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GaslessSwapHook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    struct SwapOrder {
        address trader;
        PoolKey key;
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
        uint256 deadline;
        uint256 executorFee; // Fee for the MEV executor, taken from the output amount
    }

    mapping(bytes32 => bool) public executedOrders;
    uint256 public constant FEE_DENOMINATOR = 10000;

    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("GaslessSwapHook"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function beforeSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata data
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        if (data.length > 0) {
            (SwapOrder memory order, bytes memory signature) = abi.decode(data, (SwapOrder, bytes));
            require(verifyOrder(order, signature), "Invalid signature");
            require(order.deadline >= block.timestamp, "Order expired");
            require(!executedOrders[getOrderHash(order)], "Order already executed");

            executedOrders[getOrderHash(order)] = true;

            // Transfer tokens from trader to this contract
            if (params.zeroForOne) {
                IERC20(Currency.unwrap(key.currency0)).transferFrom(order.trader, address(this), uint256(-params.amountSpecified));
            } else {
                IERC20(Currency.unwrap(key.currency1)).transferFrom(order.trader, address(this), uint256(-params.amountSpecified));
            }
        }

        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function afterSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata data
    ) external override returns (bytes4, int128) {
        if (data.length > 0) {
            (SwapOrder memory order,) = abi.decode(data, (SwapOrder, bytes));

            uint256 outputAmount;
            address outputToken;

            if (params.zeroForOne) {
                outputAmount = uint256(uint128(-delta.amount1()));
                outputToken = Currency.unwrap(key.currency1);
            } else {
                outputAmount = uint256(uint128(-delta.amount0()));
                outputToken = Currency.unwrap(key.currency0);
            }

            uint256 executorFeeAmount = (outputAmount * order.executorFee) / FEE_DENOMINATOR;
            uint256 traderAmount = outputAmount - executorFeeAmount;

            // Transfer tokens to trader and executor
            IERC20(outputToken).transfer(order.trader, traderAmount);
            IERC20(outputToken).transfer(msg.sender, executorFeeAmount);
        }

        return (this.afterSwap.selector, 0);
    }

    function getOrderHash(SwapOrder memory order) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        keccak256("SwapOrder(address trader,bytes32 poolId,bool zeroForOne,int256 amountSpecified,uint160 sqrtPriceLimitX96,uint256 deadline,uint256 executorFee)"),
                        order.trader,
                        order.key.toId(),
                        order.zeroForOne,
                        order.amountSpecified,
                        order.sqrtPriceLimitX96,
                        order.deadline,
                        order.executorFee
                    )
                )
            )
        );
    }

    function verifyOrder(SwapOrder memory order, bytes memory signature) public view returns (bool) {
        bytes32 orderHash = getOrderHash(order);
        address signer = ECDSA.recover(orderHash, signature);
        return signer == order.trader;
    }

    function createSignedOrder(
        PoolKey calldata key,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        uint256 deadline,
        uint256 executorFee,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (SwapOrder memory order, bytes memory signature) {
        order = SwapOrder({
            trader: msg.sender,
            key: key,
            zeroForOne: zeroForOne,
            amountSpecified: amountSpecified,
            sqrtPriceLimitX96: sqrtPriceLimitX96,
            deadline: deadline,
            executorFee: executorFee
        });

        signature = abi.encodePacked(r, s, v);

        require(verifyOrder(order, signature), "Invalid signature");
    }

    function executeOrder(SwapOrder memory order, bytes memory signature) external {
        bytes memory swapData = abi.encode(order, signature);

        poolManager.swap(
            order.key,
            IPoolManager.SwapParams({
                zeroForOne: order.zeroForOne,
                amountSpecified: order.amountSpecified,
                sqrtPriceLimitX96: order.sqrtPriceLimitX96
            }),
            swapData
        );
    }
}