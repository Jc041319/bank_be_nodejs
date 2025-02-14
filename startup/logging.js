// const winston = require('winston');


// module.exports = function () {
//     // Create the logger
//     const logger = winston.createLogger({
//         level: 'info',
//         transports: [
//             new winston.transports.Console({ format: winston.format.simple() }),  // Log to the console
//             new winston.transports.File({ filename: 'app.log', format: winston.format.simple() })  // Log to a file
//         ]
//     });


//     // Log unhandled promise rejections
//     process.on('unhandledRejection', (reason, promise) => {
//         logger.error('Unhandled Promise Rejection:', { reason, promise });
//         // Optionally, you can also choose to exit the process
//         process.exit(1);
//     });

//     winston.add(new winston.transports.File, { filename: 'app.log' });
//     // Example of a promise rejection that will trigger the 'unhandledRejection' event
//     // Promise.reject(new Error('Something went wrong!'));
// }

const winston = require('winston');
// require('winston-mongodb');
require('express-async-errors');

module.exports = function () {
    winston.exceptions.handle(
        // new winston.transports.File({ filename: 'uncaughtExceptions.log' })
        new winston.transports.Console({ format: winston.format.simple() }),
        new winston.transports.File({ filename: 'uncaughtExceptions.log' })

    );

    process.on('unhandledRejection', (ex) => {
        throw ex;
    });

    // winston.add(new winston.transports.File, { filename: 'logfile.log' });
    winston.add(new winston.transports.File({ filename: 'logfile.log' }));


}