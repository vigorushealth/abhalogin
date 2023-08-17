const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const helmet = require("helmet");
const dotenv = require("dotenv");
// const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const { MongoConnection } = require("./databases");
const router = require("./routes");
dotenv.config();

const app = express();
const corsOptions = {
  origin: "https://dev.d2c7oi8mimsn0e.amplifyapp.com",
  optionsSuccessStatus: 200,
  credentials: true
};

app.use(cors(corsOptions));
// const csrfProtection = csrf({ cookie: true });
app.use(helmet())
app.use((req, res, next) => {
  if (req.secure) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;");
  res.setHeader('Allow', 'GET, POST');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.json());
// app.get("/set-cookie", (req, res) => {
//   res.cookie("myCookie", "myValue", {
//     sameSite: "Strict",
//     secure: true,
//   });
//   res.send("Cookie set!");
// });
MongoConnection();

app.use("/api", router);

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log("Server is listening at", PORT);
});

module.exports = app;
