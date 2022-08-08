const express = require('express');
const router = express.Router();
const User = require('../../models/User');
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcryptjs');
const { check, validationResult} = require('express-validator');

// @route GET api/auth
// @desc Test route
// @access Public
router.get('/', auth, async (req,res) => {
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch(err){
        console.error(err.message);
        res.status(500).send('Server Error')

    }
});

// @route POST api/auth
// @desc Authenticate user & get token
// @access Public
// 1st parameter is which path it is using
// 2nd parameter is an array which checks all the conditions required
// 3rd parameter is requests and response
router.post('/',
[check('email', 'Please include a valid email').isEmail(),
 check('password','Password is required').exists()], async (req,res) => {
    // Returns all errors into an object
    const errors = validationResult(req);
    // Check if any errors and return that
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    // Make it easier to access name,email,password
    const {email,password} = req.body;


    // Login user
    try{
        // See if user exists
        let user = await User.findOne({email: email});

        if(!user){
            return res.status(400).json({errors: [{ msg: 'Invalid Credentials'}]});
        }

        const isMatch = await bcrypt.compare(password,user.password)

        if(!isMatch) {
            return res.status(400).json({errors: [{ msg: 'Invalid Credentials'}]});
        }

        // Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, 
            config.get('jwtToken'),
            {expiresIn: 360000},
            (err,token) =>{
                if(err) throw err;
                res.json({ token });
            }
            );
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;