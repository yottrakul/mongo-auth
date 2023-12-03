import express from "express";
import _ from "lodash";

import { getUserBySessionToken } from "../db/users";

export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  try {
    const sessionToken = req.cookies['MONGO-AUTH'];
    if(!sessionToken) {
      return res.sendStatus(403);
    }

    const exitingUser = await getUserBySessionToken(sessionToken);

    if(!exitingUser) {
      return res.sendStatus(403);
    }

    _.merge(req, {identity: exitingUser});

    return next();

  } catch (error) {
    console.log(error);
    return res.sendStatus(400)
  }
}

export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  try {
    const {id} = req.params;
    const currentUserId = _.get(req, 'identity._id')! as string;

    if(!currentUserId) {
      return res.sendStatus(403);
    }

    if (currentUserId.toString() !== id) {
      return res.sendStatus(403);
    }

    next();

  } catch (error) {
    console.log(error);
    return res.sendStatus(400)
  }
}
