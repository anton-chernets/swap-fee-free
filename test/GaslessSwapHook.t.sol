// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {GaslessSwapHook} from "../src/GaslessSwapHook.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {HookMiner} from "./utils/HookMiner.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {console} from "forge-std/console.sol";
// import {HookEnabledSwapRouter} from "v4-periphery-test/utils/HookEnabledSwapRouter.sol";

contract GaslessSwapHookTest is Test, Deployers {
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    GaslessSwapHook hook;
    MockERC20 token0;
    MockERC20 token1;
    // HookEnabledSwapRouter router;

    address alice = address(0x1);
    address bob = address(0x2);
    uint256 alicePrivateKey = 0x1;
    uint256 bobPrivateKey = 0x2;

    function setUp() public {
        deployFreshManagerAndRouters();
        
        // Deploy tokens
        token0 = new MockERC20("Token0", "TKN0", 18);
        token1 = new MockERC20("Token1", "TKN1", 18);

        // Ensure token0 address is less than token1 address
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }

        // Deploy the hook
        uint160 flags = uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
        );
        (address hookAddress, bytes32 salt) =
            HookMiner.find(address(this), flags, type(GaslessSwapHook).creationCode, abi.encode(address(manager)));
        hook = new GaslessSwapHook{ salt: salt }(IPoolManager(address(manager)));
        require(address(hook) == hookAddress, "hook address mismatch");

        // Create the pool
        key = PoolKey(Currency.wrap(address(token0)), Currency.wrap(address(token1)), 3000, 60, IHooks(address(hook)));
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

        // Mint tokens to this contract
        token0.mint(address(this), 1000e18);
        token1.mint(address(this), 1000e18);

        // Approve tokens
        token0.approve(address(manager), type(uint256).max);
        token1.approve(address(manager), type(uint256).max);

        console.log("Token0 balance:", token0.balanceOf(address(this)));
        console.log("Token1 balance:", token1.balanceOf(address(this)));

        // Add liquidity
        try modifyLiquidityRouter.modifyLiquidity
        (key,
        IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: 100 ether,
                salt: bytes32(0)
            }),
        ZERO_BYTES) 
        {
            console.log("Liquidity added successfully");
        } catch Error(string memory reason) {
            console.log("Failed to add liquidity:", reason);
        } catch (bytes memory lowLevelData) {
            console.log("Failed to add liquidity, low level error");
        }

        // Setup test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        token0.mint(alice, 100e18);
        token1.mint(alice, 100e18);
        token0.mint(bob, 100e18);
        token1.mint(bob, 100e18);

        console.log("Setup completed");
    }

    function testCreateSignedOrder() public {
        vm.startPrank(alice);
        token0.approve(address(hook), type(uint256).max);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            alicePrivateKey,
            hook.getOrderHash(GaslessSwapHook.SwapOrder({
                trader: alice,
                key: key,
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1,
                deadline: block.timestamp + 1 hours,
                executorFee: 100 // 1% fee
            }))
        );

        (GaslessSwapHook.SwapOrder memory order, bytes memory signature) = hook.createSignedOrder(
            key,
            true,
            -1e18,
            TickMath.MIN_SQRT_PRICE + 1,
            block.timestamp + 1 hours,
            100,
            v,
            r,
            s
        );

        assertTrue(hook.verifyOrder(order, signature), "Order verification failed");
        vm.stopPrank();
    }

    function testExecuteOrder() public {
        vm.startPrank(alice);
        token0.approve(address(hook), type(uint256).max);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            alicePrivateKey,
            hook.getOrderHash(GaslessSwapHook.SwapOrder({
                trader: alice,
                key: key,
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1,
                deadline: block.timestamp + 1 hours,
                executorFee: 100 // 1% fee
            }))
        );

        (GaslessSwapHook.SwapOrder memory order, bytes memory signature) = hook.createSignedOrder(
            key,
            true,
            -1e18,
            TickMath.MIN_SQRT_PRICE + 1,
            block.timestamp + 1 hours,
            100,
            v,
            r,
            s
        );
        vm.stopPrank();

        uint256 bobInitialBalance = token1.balanceOf(bob);
        uint256 aliceInitialBalance = token1.balanceOf(alice);

        vm.prank(bob);
        hook.executeOrder(order, signature);

        uint256 bobFinalBalance = token1.balanceOf(bob);
        uint256 aliceFinalBalance = token1.balanceOf(alice);

        assertTrue(bobFinalBalance > bobInitialBalance, "Executor did not receive fee");
        assertTrue(aliceFinalBalance > aliceInitialBalance, "Trader did not receive tokens");
    }

    function testCannotExecuteExpiredOrder() public {
        vm.startPrank(alice);
        token0.approve(address(hook), type(uint256).max);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            alicePrivateKey,
            hook.getOrderHash(GaslessSwapHook.SwapOrder({
                trader: alice,
                key: key,
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1,
                deadline: block.timestamp + 1 hours,
                executorFee: 100 // 1% fee
            }))
        );

        (GaslessSwapHook.SwapOrder memory order, bytes memory signature) = hook.createSignedOrder(
            key,
            true,
            -1e18,
            TickMath.MIN_SQRT_PRICE + 1,
            block.timestamp + 1 hours,
            100,
            v,
            r,
            s
        );
        vm.stopPrank();

        // Warp time to after the deadline
        vm.warp(block.timestamp + 2 hours);

        vm.expectRevert("Order expired");
        vm.prank(bob);
        hook.executeOrder(order, signature);
    }

    function testCannotExecuteOrderTwice() public {
        vm.startPrank(alice);
        token0.approve(address(hook), type(uint256).max);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            alicePrivateKey,
            hook.getOrderHash(GaslessSwapHook.SwapOrder({
                trader: alice,
                key: key,
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1,
                deadline: block.timestamp + 1 hours,
                executorFee: 100 // 1% fee
            }))
        );

        (GaslessSwapHook.SwapOrder memory order, bytes memory signature) = hook.createSignedOrder(
            key,
            true,
            -1e18,
            TickMath.MIN_SQRT_PRICE + 1,
            block.timestamp + 1 hours,
            100,
            v,
            r,
            s
        );
        vm.stopPrank();

        vm.prank(bob);
        hook.executeOrder(order, signature);

        vm.expectRevert("Order already executed");
        vm.prank(bob);
        hook.executeOrder(order, signature);
    }

    function testCannotExecuteOrderWithInvalidSignature() public {
        vm.startPrank(alice);
        token0.approve(address(hook), type(uint256).max);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            bobPrivateKey, // Using Bob's private key instead of Alice's
            hook.getOrderHash(GaslessSwapHook.SwapOrder({
                trader: alice,
                key: key,
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1,
                deadline: block.timestamp + 1 hours,
                executorFee: 100 // 1% fee
            }))
        );

        (GaslessSwapHook.SwapOrder memory order, bytes memory signature) = hook.createSignedOrder(
            key,
            true,
            -1e18,
            TickMath.MIN_SQRT_PRICE + 1,
            block.timestamp + 1 hours,
            100,
            v,
            r,
            s
        );
        vm.stopPrank();

        vm.expectRevert("Invalid signature");
        vm.prank(bob);
        hook.executeOrder(order, signature);
    }
}