import express from 'express'
import userAuth from '../middleware/userAuth.js'
import { getuserData } from '../controllers/userController.js'
const userRouter = express.Router()

userRouter.get('/data', userAuth, getuserData)

export default userRouter