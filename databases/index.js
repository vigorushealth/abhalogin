const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();

const MONGO_URL = process.env.MONGO_URL;

module.exports.MongoConnection = async () => {
  await mongoose.connect(MONGO_URL)
  .then(()=> {
    console.log("Database Successfully Connected");
  }).catch((err)=>{
    console.log(err);
  });
};
