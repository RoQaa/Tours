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

 app.use('/testTours',tourRouter)
 
module.exports=app;