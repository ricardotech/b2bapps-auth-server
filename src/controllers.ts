import { Request, Response } from "express";

import bcrypt from "bcrypt";

import jwt from "jsonwebtoken";
import User from "./User";

export async function SignIn(req: Request, res: Response) {
  const { email, phone_number, password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Insira sua senha" });
  }

  const user_email = await User.findOne({ email }).lean();
  const user_phone_number = await User.findOne({ phone_number }).lean();
  if (user_email) {
    const match = await bcrypt.compare(password, user_email.password);

    if (!match) {
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
      {
        _id: user_email._id,
        workspaceid: user_email.workspaceId,
        name: user_email.name,
        email: user_email.name,
        document_type: user_email.document_type,
        document_number: user_email.document_number,
        role: user_email.role,
      },
      process.env.JWT_SECRET as string,
      {
        expiresIn: "30d",
      }
    );

    return res.json({
      user: {
        id: user_email._id,
        workspaceid: user_email.workspaceId,
        name: user_email.name,
        email: user_email.name,
        role: user_email.role,
      },
      token,
    });
  }

  if (user_phone_number) {
    const match = await bcrypt.compare(password, user_phone_number.password);

    if (!match) {
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
      {
        _id: user_phone_number._id,
        workspaceid: user_phone_number.workspaceId,
        name: user_phone_number.name,
        email: user_phone_number.name,
        document_type: user_phone_number.document_type,
        document_number: user_phone_number.document_number,
        role: user_phone_number.role,
      },
      process.env.JWT_SECRET as string,
      {
        expiresIn: "30d",
      }
    );

    return res.json({
      user: {
        id: user_phone_number._id,
        workspaceid: user_phone_number.workspaceId,
        name: user_phone_number.name,
        email: user_phone_number.name,
        role: user_phone_number.role,
      },
      token,
    });
  }
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
