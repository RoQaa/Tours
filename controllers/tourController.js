const Tour=require('../models/tourModel')

exports.getAllTours=async(req,res)=>{
    try{
        const tours=await Tour.find();
        res.status(200).json({
            status:true,
            message:"Data Retrived Sucess",
            data:tours
        })


    }catch(err){
        res.status(404).json({
            status:false,
            message:"Data n't Found",
            error:err
        })
    }
}