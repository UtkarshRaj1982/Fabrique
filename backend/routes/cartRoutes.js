const express = require('express');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

//Helper function to get a cart for a user Id or guest Id
const getCart = async(userId, guestId)=>{
    if(userId){
        return await Cart.findOne({ user: userId });
    } else if(guestId){
        return await Cart.findOne({ guestId });
   }
   return null;
};

// @route POST /api/cart
// @desc Add item to cart for logged in user and guest 
// @access Public

router.post('/', async (req, res) => {

    const { productId, quantity ,size ,color ,guestId , userId } = req.body;
    try{
        const product = await Product.findById(productId);
        if(!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        // Check if the user is logged in or a guest
        let cart = await getCart(userId,guestId);

        // if the cart exists,update it 
        if(cart){
            const productIndex = cart.products.findIndex(
            (p)=>
            p.productId.toString()=== productId && 
            p.size === size && 
            p.color === color
         );
        
         if(productIndex > -1){
            //Product already exists in the cart, update the quantity
            cart.products[productIndex].quantity += quantity;   
        } else{
            //Product does not exist in the cart, add it
            cart.products.push({
                productId,
                name: product.name,
                image: product.images[0].url,
                price: product.price,
                size,
                color,
                quantity,
            });
        }
        // Recalculate the total price
        cart.totalPrice = cart.products.reduce(
            (acc, item) => acc + item.price * item.quantity, 
            0
        );
        await cart.save();
        return res.status(200).json(cart);
     } else {
        // Create a new cart for the user or guest
        const newCart = await Cart.create({
            user: userId ? userId : undefined,
            guestId: guestId ? guestId : "guest_" + new Date().getTime(),
            products: [
                {
                    productId,
                    name: product.name,
                    image: product.images[0].url,
                    price: product.price,
                    size,
                    color,
                    quantity,
                },
            ],
            totalPrice: product.price * quantity,
        });
        return res.status(201).json(newCart);
     }
    }catch(error){
        console.error('Error adding item to cart:', error);
        res.status(500).json({ message: 'Server error' });
    } 

})

// @route PUT /api/cart
// @desc Update item in cart for logged in user and guest
// @access Public

router.put('/', async (req, res) => {
    const { productId, quantity ,size ,color ,guestId , userId } = req.body;
    try{
        // Check if the user is logged in or a guest
        let cart = await getCart(userId,guestId);
        if(!cart){
            return res.status(404).json({ message: 'Cart not found' });
        }
        const productIndex = cart.products.findIndex(
            (p)=>
            p.productId.toString()=== productId && 
            p.size === size && 
            p.color === color
         );
        
         if(productIndex > -1){
            //Product already exists in the cart, update the quantity
            if(quantity > 0){
                cart.products[productIndex].quantity = quantity;   
            } else{
                // Remove the product from the cart if quantity is 0
                cart.products.splice(productIndex, 1);
            }
        
        // Recalculate the total price
        cart.totalPrice = cart.products.reduce(
            (acc, item) => acc + item.price * item.quantity, 
            0
        );
        await cart.save();
        return res.status(200).json(cart);
    } else {
            return res.status(404).json({ message: 'Product not found in cart' });
        }
    }catch(error){
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    } 

})

// @route DELETE /api/cart
// @desc Remove item from cart for logged in user and guest
// @access Public

router.delete('/', async (req, res) => {
    const { productId, size ,color ,guestId , userId } = req.body;
    try{
        // Check if the user is logged in or a guest
        let cart = await getCart(userId,guestId);
        if(!cart){
            return res.status(404).json({ message: 'Cart not found' });
        }
        const productIndex = cart.products.findIndex(
            (p)=>
            p.productId.toString()=== productId && 
            p.size === size && 
            p.color === color
         );
        
         if(productIndex > -1){
            //Product already exists in the cart, remove it
            cart.products.splice(productIndex, 1);
        
        // Recalculate the total price
        cart.totalPrice = cart.products.reduce(
            (acc, item) => acc + item.price * item.quantity, 
            0
        );
        await cart.save();
        return res.status(200).json(cart);
    } else {
            return res.status(404).json({ message: 'Product not found in cart' });
        }
    }catch(error){
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    } 
})

// @route GET /api/cart
// @desc Get cart for logged in user and guest
// @access Public

router.get('/', async (req, res) => {
    const { guestId , userId } = req.query;
    try{
        // Check if the user is logged in or a guest
        let cart = await getCart(userId,guestId);
        if(cart){
            res.json(cart);
        }else{
            res.status(404).json({ message: 'Cart not found' });
        }
    }catch(error){
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    } 
})

// @route POST /api/cart/merge
// @desc Merge guest cart with user cart
// @access Private
router.post('/merge', protect, async (req, res) => {
    const { guestId } = req.body;

    try {
        // Find the guest cart and user cart
        const guestCart = await Cart.findOne({ guestId });
        const userCart = await Cart.findOne({ user: req.user._id });
        if (guestCart) {
            if(guestCart.products.length===0) {
                return res.status(404).json({ message: 'Guest cart is empty' });
            }
        
        if (userCart) {
            // If the user cart doesn't exist, create a new one
            guestCart.products.forEach((guestItem) => {
                const ProductIndex = userCart.products.findIndex(
                    (item) =>
                        item.productId.toString() === guestItem.productId.toString() &&
                        item.size === guestItem.size &&
                        item.color === guestItem.color
                );

                if (ProductIndex > -1) {
                    // Product already exists in the user cart, update quantity
                    userCart.products[ProductIndex].quantity += guestItem.quantity;
                } else {
                    // Add new product to the user cart
                    userCart.products.push(guestItem);
                }
            });

            userCart.totalPrice = userCart.products.reduce(
                (acc, item) => acc + item.price * item.quantity,
                0
            );
            await userCart.save();

            //Remove the guest cart after merging
            try {
                await Cart.findOneAndDelete({ guestId });
            } catch (error) {
                console.error('Error deleting guest cart:', error);
            }
            res.status(200).json(userCart);
        }else{
            //If the user cart doesn't exist, create a new one
            guestCart.user = req.user.id;
            guestCart.guestId = undefined; // Remove the guestId field
            await guestCart.save();

            res.status(200).json(guestCart);
        }
    }else {
        if(userCart){
            // If the user cart exists, just return it
          return  res.status(200).json(userCart);
        }
        res.status(404).json({ message: 'Guest cart not found' });
    }
        
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});
module.exports = router;