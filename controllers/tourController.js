const Tour = require('../models/tourModel');
const AppError = require('../utils/AppError');
const { catchAsync } = require('../utils/catchAsync');


exports.getAllTours = catchAsync(async (req, res,next) => {

    const tours = await Tour.find();
    if(tours.length===0){
        return new AppError(`There's no Data to Retrive`,404)
    }
    res.status(200).json({
        status: true,
        message: "Data Retrived Sucess",
        data: tours
    })
next();

})