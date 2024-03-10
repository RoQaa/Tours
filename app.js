const express=require('express')
const morgan=require('morgan')
const tourRouter=require('./routes/tourRouter')



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
 app.use('/testTours',tourRouter)
 
module.exports=app;