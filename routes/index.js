const express = require('express');
const router = express.Router();
const {ensureAuthenticated}= require('../config/auth');

//Welcome Page
router.get('/', (req,res)=>res.render("welcome.ejs"));
//Dashboard
router.get('/dashboard', ensureAuthenticated, (req,res)=>res.render('dashboard',{
    Fname: req.user.Fname
}));

module.exports = router;