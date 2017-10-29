var express = require('express');
var router = express.Router();
const skmeans = require("skmeans");

/* GET home page. */
router.get('/', function (req, res, next) {
  let coords = [];
  req.app.locals.dataStore.forEach(report => {
    //coords.push( `new google.maps.LatLng(${report.lat},${report.lon})`);
    let threatlevel = 1;
    if (report.threatlevel === 'high') threatlevel = 3;
    if (report.threatlevel === 'medium') threatlevel = 2;

    coords.push(`[${threatlevel},${report.lat},${report.lon}, 1]`);
  })
  let coordstr = '[' + coords.join(',') + ']';

  let centreLat = 53.477131;
  let centreLon = -2.254062;
  if (req.app.locals.dataStore.length > 0) {
    centreLat = req.app.locals.dataStore.reduce((acc, report) => { return +report['lat'] + acc; }, 0) / req.app.locals.dataStore.length;
    centreLon = req.app.locals.dataStore.reduce((acc, report) => { return +report['lon'] + acc; }, 0) / req.app.locals.dataStore.length;
  }
  console.log(centreLat, centreLon)
  let alerts = analyseReports(req.app.locals.dataStore);

  res.render('index', { title: 'Lowbar: lowering the threat reporting bar', coords: coordstr, centreLat: centreLat, centreLon: centreLon, reports: req.app.locals.dataStore, alerts: alerts });
});

router.post('/reportthreat', reportThreat)


function reportThreat(req, res, next) {
  req.app.locals.dataStore.unshift(req.body); //add to front of array so most recent first

  res.status(200).send('Threat report logged');
}

function analyseReports(dataStore) {
  // let alerts = [];
  // alerts.push({threatlevel: 1, "lat": "53.477131", "lon": "-2.254062", type: 'Suspected bomb attack' });
  // alerts.push({threatlevel: 2, "lat": "53.477000", "lon": "-2.253000", type: 'Suspected vehicle attack' });
  // return alerts;
  // // // We want to look for clusters of reports in a location
  let alerts = [];
  // Should really try automated clustering but for now let's take the reports in order and detect if they are close, start a new cluster if too big gap
  let ds = dataStore;

  if (ds.length === 0) return alerts;


  // let clusters = [];
  // let clusterStart = ds[0];
  // let currentCluster = [];
  // currentCluster.push(clusterStart);
  // let distThresh = 0.25;
  // for (let i = 1; i < ds.length; i++) {
  //   if (getDistanceFromLatLonInKm(ds[i]['lat'], ds[i]['lon'], ds[i - 1]['lat'], ds[i - 1]['lon']) < distThresh) {
  //     currentCluster.push(ds[i]);
  //   } else {
  //     if (currentCluster.length === 1) {
  //       //if it's singleton, try to add to any existing cluster if it's closer than distance thresh to any point
  //       let searching = true;
  //       for (let j = 0; j < clusters.length; j++) {
  //         for (let k = 0; k < clusters[j].length; k++) {
  //           if (searching) {
  //             if (getDistanceFromLatLonInKm(currentCluster[0]['lat'], currentCluster[0]['lon'], clusters[j][k]['lat'], clusters[j][k]['lon']) < distThresh) {
  //               clusters[j].push(currentCluster[0]);
  //               currentCluster = [];
  //               currentCluster.push(ds[i]);
  //               searching = false;
  //             }
  //           }
  //         }
  //       }
  //       if (searching) {
  //         clusters.push(currentCluster);
  //         currentCluster = [];
  //         currentCluster.push(ds[i]);
  //       }
  //     }
  //     if (currentCluster.length > 1) clusters.push(currentCluster);
  //     currentCluster = [];
  //     currentCluster.push(ds[i]);
  //   }
  // }
  // if (currentCluster.length > 0) clusters.push(currentCluster);

  // // Do another pass in case we failed to assign any singletons to near clusters
  // for (let i = 0; i < clusters.length; i++) {
  //   if (clusters[i].length === 1) {
  //     for (let j = 0; j < clusters.length; j++) {
  //       if (j !== i) {
  //         for (let k = 0; k < clusters[j].length; k++) {
  //           if (clusters[i].length>0 && getDistanceFromLatLonInKm(clusters[i][0]['lat'], clusters[i][0]['lon'], clusters[j][k]['lat'], clusters[j][k]['lon']) < distThresh) {
  //             clusters[j].push(clusters[i][0]);
  //             clusters[i] = [];
  //           }
  //         }
  //       }
  //     }
  //   }
  // }

  // //tidy up
  // let newclusters=[];
  // for (let i = 0; i < clusters.length; i++) {
  //   if (clusters[i].length >0 ) {
  //     newclusters.push(clusters[i]);
  //   }
  // }
  // clusters=newclusters;




  let searching = true;
  let k = 1;
  let data = ds.map(d => { return [d.lat, d.lon]; });
  let distThresh = 0.25;
  let clusters = [];
  while (searching) {
    var res = { idxs: new Array(ds.length).fill(0), centroids: [[ds.reduce((acc, d) => { return acc + d.lat }, 0) / ds.length, ds.reduce((acc, d) => { return acc + d.lon }, 0) / ds.length]] }; // Set up all as belonging to class 0
    if (k > 1) {
      res = skmeans(data, k);
    }

    //check the distances in each cluster to neighbours - if all < distThresh we're done
    let allInRange = true;
    for (let c = 0; c < k; c++) {
      if (allInRange) {
        let inRange = true;
        //for each cluster, check each point against all others - very point should always be within distThresh of at least one other if we're done
        for (let i = 0; i < res.idxs.length; i++) {
          if (inRange && res.idxs[i] === c) {
            let thisIsCloseEnough = false;
            if (getDistanceFromLatLonInKm(ds[i]['lat'], ds[i]['lon'], res.centroids[c][0], res.centroids[c][1]) < distThresh) {
              thisIsCloseEnough = true;
            }

            inRange = inRange && thisIsCloseEnough;
          }
        }
        allInRange = allInRange && inRange;
      }
    }


    if (allInRange) {
      // we've found a partition that meets the criteria
      searching = false;
      console.log('No of clusters: ' + k)
      for (let c = 0; c < k; c++) {
        let cluster = [];
        for (let i = 0; i < res.idxs.length; i++) {
          if (res.idxs[i] === c) {
            cluster.push(ds[i]);
          }
        }
        clusters.push(cluster);
      }
    } else {
      k++;
      if (k >= data.length) searching = false;
    }
  }


  // apply some simple rules to clusters to generate auto alerts
  for (let i = 0; i < clusters.length; i++) {
    [meanLat, meanLon, meanTL] = getClusterStats(clusters[i]);
    if (clusters[i].length >= 3 && meanTL >= 2) {
      alerts.push({ threatlevel: meanTL, "lat": meanLat, "lon": meanLon, type: clusters[i].length.toString() + ' HIGH THREAT reports near' });
    } else if (clusters[i].length > 5 && meanTL >= 1) {
      alerts.push({ threatlevel: meanTL, "lat": meanLat, "lon": meanLon, type: clusters[i].length.toString() + ' MEDIUM/HIGH reports near' });
    }
    else if (clusters[i].length > 10) {
      alerts.push({ threatlevel: meanTL, "lat": meanLat, "lon": meanLon, type: 'Large number (' + clusters[i].length.toString() + ') reports near' });
    }
  }

  return alerts.sort((a, b) => { return b.threatlevel - a.threatlevel; });
}

function getClusterStats(cluster) {
  let threatscores = { 'high': 2, 'medium': 1, 'low': 0 };
  let meanLat = 0;
  let meanLon = 0;
  let meanTL = 0;
  for (let j = 0; j < cluster.length; j++) {
    meanLat += +cluster[j]['lat'];
    meanLon += +cluster[j]['lon'];
    meanTL += +threatscores[cluster[j]['threatlevel']];
  }

  meanLat /= cluster.length;
  meanLon /= cluster.length;
  meanTL = Math.round(meanTL / cluster.length);
  console.log(meanLat, meanLon, meanTL)
  return [meanLat, meanLon, meanTL];
}

function getDistanceFromLatLonInKm(lat1, lon1, lat2, lon2) {
  var R = 6371; // Radius of the earth in km
  var dLat = deg2rad(lat2 - lat1);  // deg2rad below
  var dLon = deg2rad(lon2 - lon1);
  var a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2)
    ;
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  var d = R * c; // Distance in km
  return d;
}

function deg2rad(deg) {
  return deg * (Math.PI / 180)
}

module.exports = router;
