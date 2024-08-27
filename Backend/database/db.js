const mysql = require('mysql');



const connection = mysql.createConnection({
    host: 'liquid-barker-5813.7s5.aws-ap-south-1.cockroachlabs.cloud',
    user: 'WorkiLogic',
    password: '9FIUej8Dxm9YPbb-WgJeoQ',
    database: 'defaultdb'
});

connection.connect(error => {
    if (error) {
        console.error('Error connecting to MySQL:', error);
        return;
    }
    console.log('Connected to MySQL!');
});

module.exports = connection
