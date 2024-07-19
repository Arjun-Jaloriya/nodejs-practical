const express = require("express");
const app = express();
const PORT = process.env.port || 8010;
const path = require("path");
const cors = require("cors");
const bodyparser = require("body-parser");
const connectDB = require("./db/db");
const cookieParser = require('cookie-parser');
const userRoutes = require("./routes/userRoutes");
require("dotenv").config();

connectDB();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(bodyparser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use("/user", userRoutes);
app.get("/", (req, res) => {
  res.redirect("/user/login");
});

app.listen(PORT, () => {
  console.log(`app is live at port-${PORT}`);
});
