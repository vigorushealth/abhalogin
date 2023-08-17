
const authControllers=require('../../controllers/authControllers/index');
const authorizeUser = require('../../middleware/authorizeUser');
const router=require('express').Router();

router.post('/login',authControllers.authController)
router.post('/signup',authControllers.signupController)
router.get('/refresh',authControllers.refresh)
router.get('/me',authorizeUser,authControllers.whoAmIController)
module.exports=router
