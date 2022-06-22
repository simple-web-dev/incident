const express = require('express');
const axios = require('axios').default;
const _ = require('lodash');

const app = express();

app.get('/incidents', (req, res) => {
    var incidents = [];
    var identities = {};
    var result = {};

    var incidentsEndpoints = [
        // identity api
        "https://incident-api.use1stag.elevatesecurity.io/identities/",

        // incident api
        "https://incident-api.use1stag.elevatesecurity.io/incidents/denial/",
        "https://incident-api.use1stag.elevatesecurity.io/incidents/intrusion/",
        "https://incident-api.use1stag.elevatesecurity.io/incidents/executable/",
        "https://incident-api.use1stag.elevatesecurity.io/incidents/misuse/",
        "https://incident-api.use1stag.elevatesecurity.io/incidents/unauthorized/",
        "https://incident-api.use1stag.elevatesecurity.io/incidents/probing/",
        "https://incident-api.use1stag.elevatesecurity.io/incidents/other/",
    ];

    var incidentsGetPromises = [];

    incidentsEndpoints.forEach(endpoint => {
        incidentsGetPromises.push(
            axios.get(endpoint, {
                auth: {
                    username: 'elevateinterviews',
                    password: 'ElevateSecurityInterviews2021'
                },
            })
        )
    })

    Promise.all(incidentsGetPromises)
        .then(results => {
            results.forEach((result, index) => {
                if (index == 0) {
                    if (result['status'] == 200) {
                        identities = result['data'] || {}
                    }
                } else {
                    if (result['status'] == 200) {
                        incidents = [...incidents, ...(result['data']['results'] || [])]
                    }
                }
                
            })

            incidents.forEach(incident => {
                let ipkey = incident['source_ip'] || incident['machine_ip'] || incident['ip']
                let identityKey = incident['employee_id'] || incident['reported_by'] || identities[ipkey] || incident['source_ip'] || incident['machine_ip']

                if (result[identityKey] === undefined) {
                    result[identityKey] = {
                        "low": {
                            "count": 0,
                            "incidents": []
                        },
                        "medium": {
                            "count": 0,
                            "incidents": []
                        },
                        "high": {
                            "count": 0,
                            "incidents": []
                        }
                    }
                }

                if (incident['priority'] === 'low') {
                    result[identityKey]['low']['count'] ++;
                    result[identityKey]['low']['incidents'].push(incident)
                    result[identityKey]['low']['incidents'].sort(sortByTimestamp)

                } else if (incident['priority'] === 'medium') {
                    result[identityKey]['medium']['count'] ++;
                    result[identityKey]['medium']['incidents'].push(incident)
                    result[identityKey]['medium']['incidents'].sort(sortByTimestamp)

                } else if (incident['priority'] === 'high') {
                    result[identityKey]['high']['count'] ++;
                    result[identityKey]['high']['incidents'].push(incident)
                    result[identityKey]['high']['incidents'].sort(sortByTimestamp)

                }
            })

            res.json(result)
        })
        .catch(errors => {
            console.log(errors)
            res.send("Something went wrong")
        })
})

// sort function by timestamp
const sortByTimestamp = (incident1, incident2) => {
    if (incident1['timestamp'] > incident2['timestamp']) {
        return 1
    } else {
        return -1
    }
}

app.listen(9000);