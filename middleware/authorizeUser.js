const { verifyJwtToken } = require("../utils/jwtHelper");

const authorizeUser = (req, res, next) => {
    try {
      const token = req.headers.authorization.split(" ")[1];
  
      if (!token) {
        throw Errors.noToken;
      }
  
      let decoded;
      try {
        decoded = verifyJwtToken(token);
        console.log({ decoded });
      } catch (error) {
        console.log(error);
  
        throw Errors.invalidToken;
      }
  
      if (req.allowedRoles && !req.allowedRoles.includes(decoded.role)) {
        throw Errors.unAuthorizedUser;
      }
  
      req.user = decoded;
  console.log(req.user);
  console.log(decoded);
      next();
    } catch (error) {
      res.status(error.status || 403).json({
        message: error.message,
      });
    }
  };

  module.exports=authorizeUser