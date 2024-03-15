module.exports=(err,req,res,next)=>{
    //console.log(err.stack)
    err.statusCode=err.statusCode||500; //1) gy mn el body express 2) gy mn class error
    err.status=err.status||'false';
    res.status(err.statusCode).json({
      status:err.status,
      message:err.message
  
    })
    next()
  }