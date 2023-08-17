const jwt = require("jsonwebtoken");
const User = require("../../databases/models/AbhaUser");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const { generateJwtToken } = require("../../utils/jwtHelper");
const asyncHandler = require("../../middleware/async");
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
  let { username, password } = req.body;
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
  findUser.refreshToken=refreshToken;
  const result = await findUser.save();

 res.cookie("jwt", refreshToken, {
  httpOnly: true, 
  // secure: true, 
  // sameSite: "None", 
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
  jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Forbidden" });

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
