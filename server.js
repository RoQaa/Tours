const http=require('http')
const mongoose = require('mongoose')
const dotenv = require('dotenv')

dotenv.config({ path: "./config.env" })

const DB = process.env.DATABASE.replace('<password>', process.env.PASSWORD)


mongoose.connect(DB).then((con) => {
    console.log("DB Connection Sucessfully!!")
})
const app=require('./app');
const server=http.createServer(app);

const port=process.env.PORT||3000;

server.listen(port,()=>{
    console.log(`Server Running in port ${process.env.PORT}`)
})