import "dotenv/config";
import express, { NextFunction, Response } from "express";

const router = express.Router();

import { GetUserById, SignIn, SignUp } from "./controllers";

router.get("/:userId", GetUserById);
router.post("/signin", SignIn);
router.post("/signup", SignUp);

export default router;
