const express = require("express");
const error = require("../middleware/error");
const cors = require("cors");
const config = require("config");
const dotenv = require("dotenv");
const session = require("express-session");

// Load environment variables from .env file
dotenv.config();

module.exports = function (app) {
  const auth = require("../routes/auth");

  // const allowedOrigins = config.get('allowedOrigins') || process.env.APP_114BK_ALLOWED_ORIGIN;
  const allowedOrigins = process.env.APP_114BK_ALLOWED_ORIGIN;

  const corsOptions = {
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Origin",
      "Accept",
      "Content-Length",
      "X-Requested-With",
      "x-auth-token",
      "x-auth-code",
    ],
    credentials: true,
  };

  app.use(
    session({
      secret: "MySecret",
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(cors(corsOptions));
  app.use(express.json());
  app.use("/api/auth", auth);
  app.use(error);
};
