const express = require('express');
const AccessControl = require('role-acl');
const app = express();

let grantsObject = {
    admin: {
        grants: [
            {
                resource: '/video', 
                action: '*', 
                attributes: ['*'] //field specifics, eg only title
//                 const permission = ac.can('user').execute('read').on('account');
// permission.granted;       // true
// permission.attributes;    // ['*', '!record.id']
// permission.filter(data);  // filtered data (without record.id)
            },
            {
                resource:'/video/*',
                action:'*',
                attributes:['*']
            }
        ]
    },
    user: {
        grants: [
            {
                resource: ['/video','/kiosk','/otherthing'], 
                action: 'GET', 
                attributes: ['*']
            },
            {
                resource: '/video', action: 'GET', attributes: ['*']
            },
            {
                resource: '/conflict', action: '*', attributes: ['*']
            },
            {
                resource: '/conflict', action: '!GET', attributes: ['*']
            },
            {
                resource: '/video/*', 
                // action: ['*', '!DELETE'],
                action:'GET',
                attributes: ['*']
            },
            {
                resource: '/video/*/comments', 
                action: ['GET','POST'], 
                attributes: ['*']
            },
            {
                resource: '/video/*',
                action: 'PUT',
                attributes: ['*'],
                condition: {
                            Fn: 'custom:inOwners',
                            args: { resource: 'video' }
                        }
            },
            {
                resource: '/video/*',
                action: 'DELETE',
                attributes: ['*'],
                condition: {
                            Fn: 'custom:isResourceOwner',
                            args: { resource: 'video' }
                        }
            },
        ]
    },
    anon: {
        grants: [
            {
                resource: '/video/*',
                action: 'GET',
                attributes: ["*"],
            }   
        ] 
    },
    // "sports/writer": {
    //     grants: [
    //         {
    //             resource: 'article',
    //             action: ['create', 'update'],
    //             attributes: ["*", "!status"],
    //             condition: {
    //                 Fn: 'EQUALS',
    //                 args: {
    //                     'category': 'sports'
    //                 }
    //             }
    //         }   
    //     ] 
    // },
};

const customConditions={
    myConditions: {
        categoryMatcher: (context, { type } = {}) => {
            return type && context.video.type === type;
        },
        inOwners : (context, {resource})=>{
            if (!resource) {
                return false;
            }
            if (! context[resource]){
                return false;
            }
            if (! context[resource].owners) {
                return false;
            }
            return context[resource].owners.has(context.user.name)
        },
        isResourceOwner: (context, { resource } = {}) => {
            console.log('custom condition: context: ', context,'resource', resource)
            if (!resource) {
                return false;
            }
            return context.user.name === context[resource].owner
        },
    }
}

const ac = new AccessControl(grantsObject, customConditions.myConditions);


const users={
    alice:{
        name: 'alice',
        role: 'admin'
    },
    bob:{
        name: 'bob',
        role: 'sports/editor'
    },
    billy:{
        name: 'billy',
        role: 'sports/writer'
    },
    frank:{
        name: 'frank',
        role: 'user'
    },
    charlie:{
        name: 'charlie',
        role: 'user'
    },
    jerry:{
        name: 'jerry',
        role: 'bestbuy/manager'
    },
    johnny:{
        name: 'johnny',
        role: 'bestbuy/u-johnny'
    },

    default:{
        name: 'anon',
        role: 'anon'
    }
}

const resourceTypes = {
    article:{
        type: 'article',
        owner: 'frank'
    },
    default:{}
}

const videos = {
    franks: {
        owner:'frank',
        type:'news',
        title: 'test of my powers'
    },
    123: {
        owner:'alice',
        type:'blog',
        title: 'stuff'
    },
    shared: {
        owner:'alice',
        owners: new Set(['alice','frank','bob']),
        type:'blog',
        title: 'stuff'
    },
    default:{
        owner:'mazinga',
        owners:new Set(['mazinga']),
        type: 'news',
        title: "you don't mess with mazinga z"
    }
}



// set userinfo
app.use((req, res, next) => {
  res.locals.user = users[req.query.username||'default']|| users.default; 
  res.locals.video = videos[req.query.video||'default']|| videos.default;
  console.log('res.locals:', res.locals) // group/policy lookup
  console.log(req.path, req.method);
  next();
});



app.use(async (req, res, next) => {
  const permission = await ac
    .can(res.locals.user.role)
    .execute(req.method)
    .with(res.locals) // sets context, eg category
    .on(req.path);
  console.log(permission,res.locals.user, req.method,req.path)
  if (permission.granted){
      res.status(200).json({ status: 'OK', permission });
  }
  else {
      res.status(403).json({status:'unauthorized', permission})
  }
})


app.listen(4000);