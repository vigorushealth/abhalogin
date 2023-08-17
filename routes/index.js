
const router=require('express').Router();
const authRoutes=require('./authRoute/index')
router.use('/',authRoutes)
module.exports=router
