
const authControllers=require('../../controllers/authControllers/index');
const authorizeUser = require('../../middleware/authorizeUser');
const loginLimiter = require('../../middleware/loginLimitter');
const router=require('express').Router();

router.post('/login',loginLimiter,authControllers.authController)
router.post('/signup',authControllers.signupController)
router.get('/refresh',authControllers.refresh)
router.get('/me',authorizeUser,authControllers.whoAmIController)
module.exports=router
