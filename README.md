# Locale

## A developer tool for retrieving Nigeria's geographical information

Locale is a developer tool for anyone who needs to know Nigeria, geographically at least. Locale’s API shows you all of Nigeria’s regions, states, and local government areas(LGAs). Locale is looking to be a very useful tool for the thousands of businesses building for Nigeria’s 200M+ population size. 


### Authentication
User Signup
Below is an example of a user signup
```
{
    'name': 'Kyle',
    'email': 'kyle@gmail.com',
    'password': 'kylexyz'
}
```
The user is then granted acceess to the API endpoints

### Endpoints

Get detailed geographical information about Nigeria.

- **HTTP Method:** GET
- **Endpoint:** `/regions`
- **Description:** Retrieves all Nigeria's geographical regions and information associated with it.
---
- **HTTP Method:** GET
- **Endpoint:** `/states`
- **Description:** Retrieves all the states in Nigeria and all the geographical information associated with it.

---
- **HTTP Method:** GET
- **Endpoint:** `/LGAS`
- **Description:** Retrieves all the Local Government Areas in Nigeria and all the geographical information associated with it.

---

- **HTTP Method:** GET
- **Endpoint:** `/states/<int:region_id>`
- **Description:** Retrieves all the states in a particular region and the geographical information associated with it.
---
- **HTTP Method:** GET
- **Endpoint:** `/lgas/<int:state_id>`
- **Description:** Retrieves all the LGAs in a particular state and the geographical information associated with it.


