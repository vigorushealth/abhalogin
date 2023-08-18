const jwt = require("jsonwebtoken");
const User = require("../../databases/models/AbhaUser");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const { generateJwtToken } = require("../../utils/jwtHelper");
const asyncHandler = require("../../middleware/async");
const CryptoJS=require('crypto-js')
dotenv.config();

const signupController = async (req, res) => {
  let { username, password ,role} = req.body;

  console.log({ username, password });
  try {
    if (!username || !password) {
      return res.status(400).json({ error: "All input fields are required" });
    }

    const findUser = await User.findOne({ username });
    if (findUser) {
      return res.status(409).json({ error: "User already exists" });
    }

    password = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      password,
      role
    });
    res.status(200).json(user);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal server error" });
  }
};

const authController = async (req, res) => {
const cookies=req.cookies;
  const encryptedData = req.body.encryptedData;
  console.log({encryptedData});
  const ENCRYPT_SECRET=process.env.ENCRYPT_SECRET
  // Decrypt the encrypted data using the same secret key and IV
  const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPT_SECRET);
  const decryptedData = bytes.toString(CryptoJS.enc.Utf8);

  const userData = JSON.parse(decryptedData);
  const { username, password } = userData;
  // let { username, password } = req.body;
  // // console.log({username});
  // // console.log({password});
  try {
    if (!username || !password) {
      return res.status(400).json({ error: "All input fields are required" });
    }

    const findUser = await User.findOne({ username });
    if (!findUser) {
      return res.status(404).json({ error: "No user found" });
    }

    const isPasswordMatch = await bcrypt.compare(password, findUser.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
 const payload= {
  id:findUser._id,
  username:username,
  role:findUser.role
 }
//  const expirationTimeInSeconds = parseInt('10', 10);
 const token= generateJwtToken(payload,'1m')

 const refreshToken=jwt.sign(
  { username: findUser.username },
  process.env.REFRESH_TOKEN_SECRET,
  { expiresIn: "1d" }
);
let newRefreshTokenArray =
!cookies?.jwt
    ? findUser.refreshToken
    : findUser.refreshToken.filter(rt => rt !== cookies.jwt);
    if (cookies?.jwt) {
      const refreshToken = cookies.jwt;
      const foundToken = await User.findOne({ refreshToken }).exec();
      if (!foundToken) {
          console.log('attempted refresh token reuse at login!')
          newRefreshTokenArray = [];
      }

      res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
  }

  // findUser.refreshToken=refreshToken;
  findUser.refreshToken = [...newRefreshTokenArray, refreshToken];
  const result = await findUser.save();
console.log({result});
 res.cookie("jwt", refreshToken, {
  httpOnly: true, 
  secure: true, 
  sameSite: 'none', 
  maxAge: 7 * 24 * 60 * 60 * 1000, 
});
    res.status(200).json({
      token,
      // refreshToken,
      success:"true",
      message:"Logged in successfully!",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal server error" });
  }
};


// refresh token 
const refresh=async(req,res,next)=>{
  const cookies=req.cookies;
  console.log(cookies);
  if(!cookies?.jwt){
    return res.status(401).send({message:"Unauthorized"})
  }
  
  const refreshToken=cookies.jwt;
  res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
  const foundUser = await User.findOne({ refreshToken }).exec();

  // Detected refresh token reuse!
  if (!foundUser) {
      jwt.verify(
          refreshToken,
          process.env.REFRESH_TOKEN_SECRET,
          async (err, decoded) => {
              if (err) return res.sendStatus(403); //Forbidden
              console.log('attempted refresh token reuse!')
              const hackedUser = await User.findOne({ username: decoded.username }).exec();
              hackedUser.refreshToken = [];
              const result = await hackedUser.save();
              console.log(result);
          }
      )
      return res.sendStatus(403); //Forbidden
  }
  const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken);
  jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err){
        foundUser.refreshToken = [...newRefreshTokenArray];
        const result = await foundUser.save();
        console.log(result);
        
      }
      if (err ) return res.sendStatus(403);
      const foundUser = await User.findOne({
        username: decoded.username,
      }).exec();

      if (!foundUser) return res.status(401).json({ message: "Unauthorized" });
      const payload= {
        username: foundUser.username,
        role: foundUser.role,
      }
      const token = generateJwtToken(
        payload,
         "15m" 
      );
      const newRefreshToken = jwt.sign(
        { "username": foundUser.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '1d' }
    );
    // Saving refreshToken with current user
    foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
    const result2 = await foundUser.save();
   console.log({result2});
    // Creates Secure Cookie with refresh token
    res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

      res.json({ token });
    }))
}
const whoAmIController = async (req, res) => {
  try {
    const user = req.user;
console.log(user);

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({
      message: "Something Went Wrong",
    });
  }
};
module.exports = { authController, signupController,whoAmIController ,refresh};
