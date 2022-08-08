const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult} = require('express-validator');

const User = require('../../models/User');

// @route POST api/users
// @desc Register user
// @access Public
// 1st parameter is which path it is using
// 2nd parameter is an array which checks all the conditions required
// 3rd parameter is requests and response
router.post('/',
[check('name',
 'Name is required').not().isEmpty(),
 check('email', 'Please include a valid email').isEmail(),
 check('password','Please enter a password with 6 or more characters').isLength({ min: 6})], async (req,res) => {
    // Returns all errors into an object
    const errors = validationResult(req);
    // Check if any errors and return that
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    // Make it easier to access name,email,password
    const {name,email,password} = req.body;


    // Register user
    try{
        // See if user exists
        let user = await User.findOne({email: email});

        if(user){
            return res.status(400).json({errors: [{ msg: 'User already exists'}]});
        }

        // Get users gravatar
        const avatar = gravatar.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        })

        // Create new user (does not save it)
        user = new User({
            name,
            email,
            avatar,
            password
        });
        // Encrypt password using bCrypt

        const salt = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password,salt);

        await user.save();

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