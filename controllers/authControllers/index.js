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

  // console.log({ username, password });
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
  const cookies = req.cookies;
  const encryptedData = req.body.encryptedData;
  const ENCRYPT_SECRET = process.env.ENCRYPT_SECRET;
  
  const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPT_SECRET);
  const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
  
  const userData = JSON.parse(decryptedData);
  const { username, password } = userData;
  //  const { username, password } = req.body;
  
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
  
    const payload = {
      id: findUser._id,
      username: username,
      role: findUser.role,
    };
  
    const token = generateJwtToken(payload, '2m');
  
    const refreshToken = jwt.sign(
      { username: findUser.username },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "1d" }
    );
  
    let newRefreshTokenArray = !cookies?.jwt
      ? findUser.refreshToken
      : findUser.refreshToken.filter(rt => rt !== cookies.jwt);
  
    if (cookies?.jwt) {
      const refreshTokenFromCookies = cookies.jwt;
      const foundToken = await User.findOne({ refreshToken: refreshTokenFromCookies }).exec();
  
      if (!foundToken) {
        console.log('Attempted refresh token reuse at login!');
        newRefreshTokenArray = [];
      }
    }
  
    findUser.refreshToken = [...newRefreshTokenArray, refreshToken];
    const result = await findUser.save();
    console.log('Refresh token saved:', result);
  
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  
    res.status(200).json({
      token,
      success: "true",
      message: "Logged in successfully!",
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: "An error occurred during login" });
  }
  
};


// refresh token 
const refresh=async(req,res,next)=>{
  const cookies = req.cookies;

  if (!cookies?.jwt) return res.status(401).json({ message: "Unauthorized" });

  const refreshToken = cookies.jwt;

  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Forbidden" });

      const foundUser = await User.findOne({
       refreshToken
      }).exec();

      if (!foundUser) return res.status(401).json({ message: "Unauthorized" });
     else{
      const token = jwt.sign(
        {
          UserInfo: {
            username: foundUser.username
          },
        },
        process.env.SECRET_KEY,
        { expiresIn: "15m" }
      );

      res.json({ token });
     }
    })
  ); 
}
const whoAmIController = async (req, res) => {
  try {
    const user = req.user;

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({
      message: "Something Went Wrong",
    });
  }
};
module.exports = { authController, signupController,whoAmIController ,refresh};
