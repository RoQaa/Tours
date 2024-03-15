const express=require('express')
const morgan=require('morgan')
const tourRouter=require('./routes/tourRouter')
const userRouter=require('./routes/userRouter')
const AppError=require('./utils/AppError')
const globalErrorHandler=require('./controllers/errorController')

const app=express();

// 1) MIDDLEWARES
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  }

  app.use(express.json());
 // app.use(express.static(`${__dirname}/public`));
app.get('/',(req,res)=>{
  res.status(200).json({
    status:true,
    message:"Welcom TO Our Appllication u connected Successfully"
  })
})
  app.use('/api',userRouter)
 app.use('/testTours',tourRouter)


app.all('*',(req,res,next)=>{ 

  next(new AppError(`Can't find ${req.originalUrl}`,404))

})
//Global Handler Errors
app.use(globalErrorHandler)
module.exports=app;