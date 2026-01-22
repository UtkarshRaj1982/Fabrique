const express = require('express');
const Checkout = require('../models/Checkout');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const Order = require('../models/Order');
const { protect } = require('../middleware/authMiddleware');
const router = express.Router();

// @route POST /api/checkout
// @desc Create a checkout session for logged in user and guest
// @access Public

router.post('/',protect, async (req, res) => {
  const { checkoutItems, shippingAddress, paymentMethod, totalPrice} = req.body;
    if(!checkoutItems || checkoutItems.length === 0){
        return res.status(400).json({message:'No items in the checkout'});
    }

    try{
        // Create a new checkout session
        const newCheckout = new Checkout({
            user: req.user._id,
            checkoutItems:checkoutItems,
            shippingAddress,
            paymentMethod,
            totalPrice,
            paymentStatus:'Pending',
            isPaid:false,
        });

        await newCheckout.save();
        console.log(`checkout session created for user: ${req.user._id}`);
        
        res.status(201).json(newCheckout);
    }catch(error){
        console.error("Error creating checkout sessions:",error);
        res.status(500).json({ message: 'Server error' });
    }
});

// @route PUT /api/checkout/:id/pay
// @desc Update checkout to mark as paid after successful payment
// @access Private
router.put('/:id/pay', protect, async (req, res) => {
    const {paymentStatus, paymentDetails } = req.body; 

    try {
        const checkout = await Checkout.findById(req.params.id);
        if (!checkout) {
            return res.status(404).json({ message: 'Checkout not found' });
        }

        if(paymentStatus === "paid"){
        checkout.isPaid = true;
        checkout.paymentStatus = paymentStatus; // Update payment status to 'paid';
        checkout.paymentDetails = paymentDetails;
        checkout.paidAt = Date.now();
        await checkout.save();

        res.status(200).json(checkout);
        }else{
            // If payment is not successful, return an error message
            res.status(400).json({ message: 'Payment failed' });
        }
        
    } catch (error) {
        console.error('Error updating checkout:', error);
        res.status(500).json({ message: 'Server error' });
    }
})

// @route POST /api/checkout/:id/finalize
// @desc Finalize the checkout and create an order after payment confirmation
// @access Private
router.post('/:id/finalize', protect, async (req, res) => {
    try {
        const checkout = await Checkout.findById(req.params.id);

        if (!checkout) {
            return res.status(404).json({ message: 'Checkout not found' });
        }

        if(checkout.isPaid && !checkout.isFinalized){
            // Create final order based on the checkout details
            const finalOrder = await Order.create({
                user:checkout.user,
                orderItems:checkout.checkoutItems,
                shippingAddress:checkout.shippingAddress,
                paymentMethod:checkout.paymentMethod,
                totalPrice:checkout.totalPrice,
                isPaid:true,
                paidAt:checkout.paidAt,
                isDelivered:false,
                paymentStatus:"paid",
                paymentDetails:checkout.paymentDetails,    
        });

        // Mark the checkout as finalized
        checkout.isFinalized = true;
        checkout.finalizedAt = Date.now();
        await checkout.save();
        // Delete the cart associated with the user
        await Checkout.findOneAndDelete({user:checkout.user});
        res.status(201).json(finalOrder);
      } else if(checkout.isFinalized){
            return res.status(400).json({ message: 'Checkout already finalized' });
        }else{
            return res.status(400).json({ message: 'Checkout is not paid' });
        }
    } catch (error) {
        console.error('Error finalizing checkout:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;