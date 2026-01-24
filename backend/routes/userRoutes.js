const express = require('express');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { protect } = require('../middleware/authMiddleware');
const router = express.Router();

// @route POST /api/users/register
// @desc Register a new user
// @access Public

router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
       // Validate input
       if (!name || !email || !password) {
         return res.status(400).json({ message: 'Please provide name, email, and password' });
       }

       //Registration logic 
       let user = await User.findOne({ email });
       if(user){
        return res.status(400).json({message:'User already exists'});
       }
       
       user = new User({
        name,
        email,
        password
       });
       await user.save();

      //create jwt payload

      const payload = {user:{id:user._id,role:user.role}};

      jwt.sign(payload,process.env.JWT_SECRET,{expiresIn:"40h"},(err,token)=>{
        if(err) {
          console.error('JWT sign error:', err);
          return res.status(500).json({ message: 'Error creating token' });
        }

        // Send the user and token in response
        res.status(201).json({
            user:{
                _id:user._id,
                name:user.name,
                email:user.email,
                role:user.role
            },
            token,
        });
      });

    } catch (error) {
        console.error('Registration error:', error);
        // Handle Mongoose validation errors
        if (error.name === 'ValidationError') {
          const messages = Object.values(error.errors).map(e => e.message);
          return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: error.message || 'Server error during registration' });
    }
});

// @route POST /api/users/login
// @desc Login user
// @access Public

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    //find the user by email
    let user =await User.findOne({ email });
    if(!user){
      return res.status(400).json({message:'Invalid Credentials'});
    }
    const isMatch = await user.matchPassword(password);
    if(!isMatch){
      return res.status(400).json({message:'Invalid Credentials'});
    }

      //create jwt payload

      const payload = {user:{id:user._id,role:user.role}};

      jwt.sign(payload,process.env.JWT_SECRET,{expiresIn:"40h"},(err,token)=>{
        if(err) {
          console.error('JWT sign error:', err);
          return res.status(500).json({ message: 'Error creating token' });
        }
        res.status(200).json({
            user:{
                _id:user._id,
                name:user.name,
                email:user.email,
                role:user.role
            },
            token,
        });
      });
 
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: error.message || 'Server error during login' });
  }
})

// @route GET /api/users/profile
// @desc Get logged in user profile (Protected Route)
// @access Private

router.get('/profile',protect , async (req, res) => {
  res.json(req.user);
})

module.exports = router;
