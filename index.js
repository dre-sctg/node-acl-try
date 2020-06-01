const express = require('express');
const AccessControl = require('role-acl');
const app = express();

let grantsObject = {
    admin: {
        grants: [
            {
                resource: '/video', action: '*', attributes: ['*']
            }
        ]
    },
    user: {
        grants: [
            {
                resource: 'video', action: 'create', attributes: ['*']
            },
            {
                resource: 'video', action: 'read', attributes: ['*']
            },
            {
                resource: 'video', action: 'update', attributes: ['*']
            },
            {
                resource: 'video', action: 'delete', attributes: ['*']
            },
        ]
    },
    "sports/editor": {
        grants: [
            {
                resource: 'article',
                action: '*',
                attributes: ["*"],
                condition: {
                    Fn: 'EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }   
        ] 
    },
    "sports/writer": {
        grants: [
            {
                resource: 'article',
                action: ['create', 'update'],
                attributes: ["*", "!status"],
                condition: {
                    Fn: 'EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }   
        ] 
    },
    "custom/writer":{
        grants: [
            {
                role: 'editor/news',
                resource: 'article',
                action: 'approve',
                attributes: ['*'],
                // Mix core with custom conditions
                condition: {
                    Fn: 'AND',
                    args: [
                        {
                            Fn: 'custom:categoryMatcher',
                            args: { type: 'news' }
                        },
                        {
                            Fn: 'custom:isResourceOwner',
                            args: { resource: 'article' }
                        }
                    ]
                }
            },
        ]
    }
};

const customConditions={
    myConditions: {
        categoryMatcher: (context, { type } = {}) => {
            // A naive use of the JSON path util
            // Keep in mind it comes with performance penalties
            return type && getValueByPath(context, '$.category.type') === type;
        },
        isResourceOwner: (context, { resource } = {}) => {
            if (!resource) {
                return false;
            }
            return getValueByPath(context, `$.${resource}.owner`) === getValueByPath(context, '$.user.id');
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
    jerry:{
        name: 'jerry',
        role: 'custom/writer'
    },
    default:{
        name: 'anon',
        role: 'anon'
    }
}




// set userinfo
app.use((req, res, next) => {
  res.locals.user = users[req.query.username||'default']; 
  console.log('res.locals.user:', res.locals.user) // group/policy lookup
  console.log(req.path, req.method);
  next();
});



app.use(async (req, res, next) => {
  const permission = await ac
    .can(res.locals.user.role)
    .execute(req.method)
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