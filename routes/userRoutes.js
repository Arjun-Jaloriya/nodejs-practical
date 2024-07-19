const express = require("express");
const {
  redirectRegisterpage,
  redirectLoginpage,
  register,
  login,
  redirectDashboard,
  logout,
  changePassword,
  redirectChangePassword,
  
} = require("../controllers/userController");
const isAuthenticate = require("../middleware/auth");
const userRouter = express.Router();

userRouter.get("/register", redirectRegisterpage);
userRouter.post("/register", register);
userRouter.get("/login", redirectLoginpage);
userRouter.post("/login", login);
userRouter.get("/dashboard", isAuthenticate, redirectDashboard);
userRouter.get("/changePassword", isAuthenticate, redirectChangePassword);
userRouter.post("/changePassword", isAuthenticate, changePassword);
userRouter.get("/logout", isAuthenticate, logout);

module.exports = userRouter;
