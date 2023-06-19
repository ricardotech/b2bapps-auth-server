import { Request, Response } from "express";

import bcrypt from "bcrypt";

import jwt from "jsonwebtoken";
import User from "./User";

export async function SignIn(req: Request, res: Response) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  const user = await User.findOne({ email }).lean();
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(400).json({ error: "Wrong password" });
  }

  const token = jwt.sign(
    {
      _id: user._id,
      workspaceid: user.workspaceId,
      name: user.name,
      email: user.name,
      document_type: user.document_type,
      document_number: user.document_number,
      role: user.role,
    },
    process.env.JWT_SECRET as string,
    {
      expiresIn: "30d",
    }
  );

  return res.json({
    user: {
      id: user._id,
      workspaceid: user.workspaceId,
      name: user.name,
      email: user.name,
      role: user.role,
    },
    token,
  });
}

export async function SignUp(req: Request, res: Response) {
  let { email, name, password, workspaceId } = req.body;

  workspaceId = "1";

  if (!name) {
    return res.status(400).json({ error: "Missing name" });
  }

  if (!workspaceId) {
    return res.status(400).json({ error: "Missing workspaceId" });
  }

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  const crypted_password = await bcrypt.hash(password, 10);

  const user = new User({
    name,
    email,
    password: crypted_password,
    workspaceId,
    role: "user",
  });

  await user.save();

  const token = jwt.sign(
    {
      id: user._id,
      workspaceid: user.workspaceId,
      name: user.name,
      email: user.name,
      role: user.role,
    },
    process.env.JWT_SECRET as string,
    {
      expiresIn: "30d",
    }
  );

  return res.json({
    user: {
      _id: user._id,
      workspaceid: user.workspaceId,
      name: user.name,
      email: user.name,
      role: user.role,
    },
    token,
  });
}

export async function GetUserById(req: Request, res: Response) {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).json({ error: "Missing userId" });
  }

  const user = await User.findById(userId).lean();

  return res.json(user);
}
