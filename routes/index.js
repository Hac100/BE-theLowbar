var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Lowbar: lowering the threat reporting bar', coords: '[    new google.maps.LatLng(53.477131, -2.254062),            new google.maps.LatLng(53.477, -2.254062),            new google.maps.LatLng(53.477, -2.2530),            new google.maps.LatLng(53.477131, -2.253)   ];' });
});

module.exports = router;
