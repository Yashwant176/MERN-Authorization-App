import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import cookieParser from 'cookie-parser'
import connectDB from './config/mongodb.js'
import authRouter from './routes/authRoutes.js'
import userRouter from './routes/userRoutes.js'
const app=express()
const port= process.env.PORT || 4000
connectDB();

app.use(express.json())
app.use(cookieParser())
const allowedOrigins = ['http://localhost:5173']

app.use(cors({
  origin: function(origin, callback){
    // allow requests with no origin (like Postman or server-to-server)
    if(!origin) return callback(null, true);
    if(allowedOrigins.indexOf(origin) === -1){
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, origin);
  },
  credentials: true
}));

app.get('/',(req,res)=>{
    res.send("api working")
})
app.use('/api/auth', authRouter)
app.use('/api/user', userRouter)
app.listen(port,()=>console.log(`server started on PORT: ${port}`)) 