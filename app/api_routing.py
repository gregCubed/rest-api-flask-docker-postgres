from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import cross_origin
import os
import json
import psycopg
import logging
from psycopg.rows import dict_row
import requests
import jwt

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

debug_value = False
# debug_value = True

store_name = "SAMPLE STORE KEY"
database_name = "SAMPLE DB KEY"
tax_provider = "SAMPLE TAX PROVIDER"

dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) # rest-api-flask-docker-postgres (parent of parent directory `./app`)
with open(f"{dir_path}/config/bigcommerce.json", "r") as f:
    config_bc_json = json.load(f)
with open(f"{dir_path}/config/bigcommerce-storefront.json", "r") as f:
    config_bc_storefront_json = json.load(f)

if debug_value: logging.basicConfig(format='[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%b-%d %H:%M:%S')
else: logging.basicConfig(format='[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s', level=logging.INFO, datefmt='%Y-%b-%d %H:%M:%S')

store_hash = config_bc_json[store_name]['storeHash']
headers = {
    "Content-Type": "application/json",
    "X-Auth-Token": config_bc_json[store_name]['accessToken']
}

with open(f"{dir_path}/config/postgresql.json", "r") as f:
    config_sql_json = json.load(f)

config_ins_json = config_sql_json[database_name]
try:
    init_conn = psycopg.connect(dbname=config_ins_json['database'], user=config_ins_json['username'], password=config_ins_json['password'], host=config_ins_json['host'], port=config_ins_json['port'])
    init_conn.close()
except psycopg.OperationalError as e:
    logging.error(f"Encountered {type(e).__name__} when attempting to connect to PostgreSQL server")
    exit()

def jwt_decode(token:str,
    key_decode=config_bc_storefront_json[store_name]['clientSecret'],
    aud=config_bc_storefront_json[store_name]['clientId'],
    algos:list=["HS512"]):
    try:
        return jwt.decode(token, key=key_decode, audience=aud, algorithms=algos)
    except (jwt.exceptions.InvalidSignatureError, jwt.exceptions.InvalidAlgorithmError, jwt.exceptions.ExpiredSignatureError,
    jwt.exceptions.DecodeError) as e:
        return e

def exec_query(query:str, ret_version:str = None, values = None):
    conn = psycopg.connect(dbname=config_ins_json['database'], user=config_ins_json['username'], password=config_ins_json['password'], host=config_ins_json['host'], port=config_ins_json['port'], options='-c statement_timeout=60000')
    cursor = conn.cursor(row_factory=dict_row)
    logging.debug(f"Started PostgreSQL connection with closed status {conn.closed}")
    try:
        if not values: cursor.execute(query)
        else: cursor.execute(query, values)
        conn.commit()
        if ret_version == "fetchone": ret = cursor.fetchone()
        elif ret_version == "fetchall": ret = cursor.fetchall()
        elif ret_version == "status": ret = cursor.statusmessage
        else: ret = None
    except (psycopg.OperationalError, psycopg.InternalError) as e:
        logging.error(f"Encountered psycopg error {type(e).__name__}:", exc_info=True)
        conn.rollback()
        ret = "null"
    conn.close()
    logging.debug(f"Closed PostgreSQL connection with closed status {conn.closed}")
    return ret

def assign(mapping:dict, key:str, fail):
    try: return mapping[key]
    except KeyError: return fail

def map_ship_friendly(ship_method_desc:str, ship_method:str):
    """ maps given `ship_method_desc` to its 'friendly' name """
    friendly = {
        "DHLTB": "DHL 15+ Business Days (Depending on Country)",
        "FDXC": "FedEx 2 Day",
        "MAIL": "USPS Mail",
        "UPS2": "UPS Second Day",
        "UPSGTB": "UPS Ground",
        "UPSN": "UPS Overnight",
        "UPSNTB": "UPS Next Day",
        "F2DA": "FedEx 2 Day",
        "FGND": "FedEx Ground",
        "FHDL": "FedEx Home Delivery",
        "FINTLE": "FedEx Intl Economy",
        "FPRI": "FedEx Priority Overnight",
        "FSP": "FedEx SmartPost",
        "LGINTEXP": "Landmark International Express",
        "OTGND": "Ontrac Ground",
        "U2DA": "UPS 2nd Day Air",
        "U3DS": "UPS 3 Day Select",
        "UGND": "UPS Ground",
        "UNDA": "UPS Next Day Air",
        "UPS": "UPS Shipping",
        "UPSSPP": "UPS SurePost Over 1LB",
        "UPWS": "UPS Worldwide Saver",
        "USPM": "USPS Priority Mail",
        "USPP": "USPS Parcel Select",
        "USPPS": "UPS Shipping"
    }
    try: return friendly[ship_method_desc]
    except KeyError: return ship_method

def map_ship_carrier(ship_method_desc:str):
    carrier = {
        "DHLTB": "US Postal Service",
        "FDXC": "FedEx",
        "MAIL": "US Postal Service",
        "UPS2": "UPS",
        "UPSGTB": "UPS",
        "UPSN": "UPS",
        "UPSNTB": "UPS",
        "UPSO": "UPS",
        "F2DA": "FedEx",
        "FGND": "FedEx",
        "FHDL": "FedEx",
        "FINTLE": "FedEx",
        "FPRI": "FedEx",
        "FSP": "FedEx",
        "LGINTEXP": "Landmark",
        "OTGND": "Ontrac",
        "U2DA": "UPS",
        "U3DS": "UPS",
        "UGND": "UPS",
        "UNDA": "UPS",
        "UPS": "UPS",
        "UPSSPP": "UPS",
        "UPWS": "UPS",
        "USPM": "US Postal Service",
        "USPP": "US Postal Service",
        "USPPS": "UPS",
    }
    try: return carrier[ship_method_desc]
    except KeyError: return ship_method_desc

@app.route('/', methods=['GET'])
def home():
    return "<h1>Testing, Testing 1 2 3</h1><p>Lorem ipsum dolor eres sat golum vas sera horis. Dustin Brown is a King.</p>"

@app.route('/taxes/<tax_acct_num>', methods=['GET'])
@cross_origin()
def TaxExemptAccounts(tax_acct_num:str):
    entry = exec_query(f"SELECT * FROM schema.tax_exempt_accts WHERE tax_account_num = '{tax_acct_num}'", "fetchone")
    if entry == "null": # if entry = "null" as a result of error during exec_query()
        logging.error(f"Error occurred when attempting to lookup {tax_acct_num}")
    if debug_value: logging.debug(entry)
    if entry == None: return jsonify(False), 404 # account not eligible for tax exemption due to not having entry in table
    elif int(entry['taxable']) == 0: # if account has non-taxable status
        if entry['expiration_date'] and entry['expiration_date'] < datetime.now().date(): # if account has expiration date AND expiration date is before today
            return jsonify(False), 200 # account not eligible for tax exemption, but entry was found
        else:
            return jsonify(True), 200 # account eligible for tax exemption
    else:
        return jsonify(False), 200 # account not eligible for tax exemption

@app.route('/orders/history', methods=['GET'])
@cross_origin()
def OrderHistory(): # set for 10 at a time, include pagination
    data = request.args
    # for prod
    # data = {
    #   "jwt":"super.long.string"
    #   "email":"email@test.com"
    #   "page":1
    #   "limit":10
    # }
    # page and limit can be either str or int
    # logging.debug(data)
    if not debug_value:
        try: data['jwt']
        except KeyError:
            err = {"error": f"A JWT was not submitted, please check your request"}
            logging.error(err['error'])
            return jsonify(err), 403
        try:
            token_info = jwt_decode(data['jwt'])
            # logging.debug(token_info)
            if token_info['customer']['email'] != data['email']: raise ValueError
        except TypeError:
            try: raise token_info
            except jwt.exceptions.DecodeError:
                err = {"error": f"Invalid JWT submitted, or it could not be decoded"} # return generic message to request to obfuscate any issue
                logging.error(err)
                return jsonify(err), 403
            except jwt.exceptions.ExpiredSignatureError:
                err = {"error": f"Invalid JWT submitted, or it could not be decoded"}
                secure_warn = f"SECURITY_ERROR: An expired token has been used to attempt to access {data['email']}'s order history."
                logging.error(secure_warn)
                return jsonify(err), 403
        except ValueError:
            err = {"error": f"Invalid JWT submitted, or it could not be decoded"}
            secure_warn = f"SECURITY_ERROR: The user {token_info['customer']['email']} has attempted to access the order history of {data['email']}."
            logging.error(secure_warn)
            return jsonify(err), 403
    try:
        limit = int(data['limit'])
        offset = (int(data['page'])-1)*limit
    except ValueError as e:
        err = {"error": f"Error occurred when attempting to convert pagination data to numbers with message {e}"}
        logging.error(err)
        return jsonify(err), 403
    if debug_value: logging.debug(f"limit: {limit}, offset: {offset}")
    # TODO change limit/offset requirements for certain # of orders
    # entry = exec_query(
    #     f"SELECT * FROM schema.salesorder WHERE email_address = '{data['email']}'", "fetchall")
    entry_view = exec_query(
        f"""SELECT DISTINCT billname,billcompany,billaddress,billcity,billstate,billpostal,billcountry,currency,credit_card_type
        shipname,shipcompany,shipaddress,shipcity,shipstate,shippostal,shipcountry,show_pricing,
        ordernumber,orderdate,creation_date,order_shipping_total,shipping_tax_total,
        ordernotes,handling_instructions_note,customer_number,email_address
            FROM schema.shipconf_email
            WHERE email_address = '{data['email']}'""", "fetchall")
    if entry_view != "null":
        for row in entry_view:
            item = exec_query(
                f"""SELECT DISTINCT item_description,engraving_order,engraving_desc,engraving_text,orderlinenumber,
                quantity,sku,unit_price,unit_tax,unit_discount,shipment_line_id,shipped_date,tracking_number,
                shipped_quantity,cancelled_quantity,shipmethod,ship_method,ship_method_desc
                    FROM schema.shipconf_email
                    WHERE ordernumber = '{row['ordernumber']}'""", "fetchall")
            if item: row['items'] = item
            else: row['items'] = "null"
    elif not entry_view: # if entry = None due to no entry in database
        entry_view = []
    else: # if entry_view == "null" bc entry threw error during exec_query()
        logging.error(f"Error occurred when attempting to find order history for customer with email {data['email']}")
        entry_view = None

    # search salesorder regardless of outcome in shipconf_email
    not_search_orders = ", ".join(f"'{num['ordernumber']}'" for num in entry_view)
    if not_search_orders:
        entry = exec_query(
            f"""SELECT * FROM schema.salesorder WHERE email_address = '{data['email']}'
                AND order_number NOT IN ({not_search_orders})""", "fetchall")
    else:
        entry = exec_query(f"SELECT * FROM schema.salesorder WHERE email_address = '{data['email']}'", "fetchall")
    if entry != "null":
        for row in entry:
            item = exec_query(f"SELECT * FROM schema.salesorderitem WHERE order_number = '{row['order_number']}'", "fetchall")
            if item: row['items'] = item
            else: row['items'] = "null"
    elif not entry: # if entry = None due to no entry in database
        entry = []
    else: # if entry == "null" bc entry threw error during exec_query()
        logging.error(f"Error occurred when attempting to find order history for customer with email {data['email']}")
        entry = None
    for order in entry:
        entry_view.append(order)
    # logging.debug(json.dumps(entry_view, indent=2, default=str))
    
    return jsonify(entry_view), 200
    # return page number, limit of orders per page, and results in page

@app.route('/orders/status', methods=['GET'])
@cross_origin()
def OrderStatus():
    data_md = request.args
    # data = {
    #   "email":"email@test.com"
    #   "orderNumber":"1234567890"
    # }
    data = data_md.to_dict()
    # logging.debug(data)
    
    try:
        data['order_number'] = data['orderNumber']
    except KeyError:
        if data['order_number']:
            pass
    # if str(data['order_number'])
    # entry = exec_query(f"""SELECT * FROM schema.shipconf_email WHERE email_address = '{data['email']}' AND
    #     (order_number = '{data['order_number']}'""", "fetchall")
    entry = exec_query(f"""SELECT DISTINCT order_number,email_address,creation_date,ship_name,ship_street_address,
        ship_suite_apartment,ship_city,ship_state,ship_postal_code,order_date,subtotal,shipping_total,tax_total,total
        FROM schema.shipconf_email
        WHERE LOWER(email_address) = LOWER('{data['email']}') AND
        (order_number = UPPER('{data['order_number']}'))""", "fetchall")
    
    if entry and entry != "null":
        for row in entry:
            item = exec_query(
                f"""SELECT shipment_line_id,shipped_date,tracking_number,ship_method,ship_method_desc,item_number,item_description,
                ordered_quantity,shipped_quantity,cancelled_quantity,backordered_quantity,unit_price,unit_discount,unit_total_cost,
                available_date,dropship_item,intl_vat_total,intl_duty
                FROM schema.shipconf_email WHERE order_number = '{row['order_number']}'""", "fetchall")
            if item:
                row['items'] = item
                for indv_item in item:
                    indv_item['ship_method'] = map_ship_carrier(indv_item['ship_method_desc'])
                    indv_item['ship_method_desc'] = map_ship_friendly(indv_item['ship_method_desc'], indv_item['ship_method'])
            else: row['items'] = "null"
    elif not entry: # if entry = None due to no entry in database
        entry = exec_query(
            f"""SELECT * FROM schema.salesorder WHERE LOWER(email_address) = LOWER('{data['email']}')
            AND order_number = UPPER('{data['order_number']}')""", "fetchall")
        if entry != "null":
            for row in entry:
                item = exec_query(f"SELECT * FROM schema.salesorderitem WHERE order_number = '{row['order_number']}'", "fetchall")
                if item: row['items'] = item
                else: row['items'] = "null"
        else: # if entry == "null" bc entry threw error during exec_query()
            logging.error(f"Error occurred when attempting to find status for order with email {data['email']} and number {data['order_number']}")
            entry = None
    else: # if entry == "null" bc entry threw error during exec_query()
        logging.error(f"Error occurred when attempting to find status for order with email {data['email']} and number {data['order_number']}")
        entry = None

    # logging.debug(json.dumps(entry, indent=2, default=str))
    if entry: return jsonify(entry), 200
    else: return [], 204
    
@app.route('/orders/return', methods=['POST'])
@cross_origin()
def OrderReturnRequest():
    data = request.json
    logging.debug(data)
    columns = { # live data model
        "return_id":"",
        "order_id":"",
        "sku_id":"",
        "qty_to_return":"",
        "reason_code":"",
        "creation_date":"",
        "email_address":"",
        "original_order_date":"",
        "shipment_id":"",
        "resolution_code":"",
        "item_description":""
    }
    columns['return_id'] = "READY"
    columns['order_id'] = data['order_id']
    columns['sku_id'] = data['sku_id']
    columns['qty_to_return'] = data['qty_to_return']
    columns['reason_code'] = data['reason_code']
    columns['email_address'] = data['email_address']
    columns['original_order_date'] = data['original_order_date']
    columns['shipment_id'] = data['shipment_id']
    columns['resolution_code'] = data['resolution_code']
    columns['item_description'] = data['item_description']
    
    nu_columns = {k:v for k,v in columns.items() if v} # makes new dict from `columns` removing empty strings
    keys = ", ".join(key for key in nu_columns.keys()) # string
    keys_list = [f"%({key})s" for key in nu_columns.keys()] # list of modified strings
    keys_str = ", ".join(key for key in keys_list) # string of modified strings

    status_msg = exec_query(f"INSERT INTO schema.returns ({keys}) VALUES ({keys_str});", "status", nu_columns)
    if status_msg != "null":
        logging.info(f"Return {columns['order_id']} of SKU {columns['sku_id']} inserted into schema.fc_returns with response: {status_msg}")
    else: # if status_msg = "null" as a result of error during exec_query()
        logging.error(f"Error occurred when attempting to return {columns['sku_id']} in order {columns['order_id']} into schema.fc_returns")
        return jsonify(), 400

    return jsonify(), 201

@app.route('/taxinfo/auth', methods=['GET'])
@cross_origin()
def TaxInfoAuth():
    data = request.args
    oauth2_url = "https://login.taxinfo.com/oauth2/token"
    taxinfo_auth_headers = {
        "Content-Type": "application/json"
    }
    taxinfo_payload = {
        "client_id": config_bc_storefront_json[tax_provider]['clientId'],
        "client_secret": config_bc_storefront_json[tax_provider]['clientSecret'],
        "code": data['code'],
        "context": data['context'],
        "scope": data['scope'],
        "grant_type": "authorization_code",
        "redirect_uri": "https://suburl.storename.com/taxinfo/auth"
    }
    oauth2_req = requests.request("POST", oauth2_url, headers=taxinfo_auth_headers, json=taxinfo_payload)
    return jsonify(oauth2_req.text), oauth2_req.status_code

@app.route('/taxinfo/load', methods=['GET'])
@cross_origin()
def TaxInfoLoad():
    data = request.args
    data_info = jwt_decode(data['signed_payload_jwt'],
    config_bc_storefront_json[tax_provider]['clientSecret'],
    config_bc_storefront_json[tax_provider]['clientId'], ["HS256"])
    try:
        if data_info['user']: return jsonify(data_info), 200
    except KeyError: return jsonify(data_info), 400

@app.route('/taxinfo/uninstall', methods=['GET'])
@cross_origin()
def TaxInfoUninstall():
    return jsonify(), 201

@app.route('/taxes/estimate', methods=['POST'])
@cross_origin()
def TaxInfoEstimate():
    data = request.json
    docu_return = []
    # logging.info("info from BC:")
    # logging.info(json.dumps(data, indent=2))
    debug_log_taxes = False # gets changed later in script so don't set to true unless yk what you're doing
    while data['documents']:
        documents = data['documents'].pop()
        items = documents['items'] # copy data['documents'] to local var, then use while w/ pop to fill out items
        # logging.debug(json.dumps(data, indent=2))
        taxed_items = []
        for item in items:
            if item['tax_exempt']: continue
            else:
                taxed_items.append({
                    "ActualExtendedPrice": item['price']['amount'],
                    "ItemKey": item['id'],
                    "Quantity": item['quantity'],
                    "ItemDescription": item['name']
                })

        txinfo_payload = {
            "CalculateTax": {
                "Security": {
                    "Password": config_bc_json[store_name]['taxinfoPW']
                },
                "IsCommitted": False,
                "TaxDate":data['transaction_date'],
                "Lines": taxed_items,
                "DestinationAddress": {
                    "Street1": assign(documents['destination_address'], 'line1', documents['billing_address']['line1']), #0
                    "City": assign(documents['destination_address'], 'city', documents['billing_address']['city']), #0
                    "Region": documents['destination_address']['region_code'], #0
                    "PostalCode": documents['destination_address']['postal_code'] #0
                }
            }
        }
        # logging.info("info to taxinfo:")
        # logging.info(json.dumps(txinfo_payload, indent=2))
        if not txinfo_payload['CalculateTax']['DestinationAddress']['Region']:
            txinfo_payload['CalculateTax']['DestinationAddress']['Country'] = documents['destination_address']['country_code'] #0

        txinfo_estimate_url = "https://ws.taxinfo.co/taxinfo/1.1/CalculateTax"
        txinfo_estimate_req = requests.request("POST", txinfo_estimate_url, json=txinfo_payload)
        # logging.info("response from taxinfo:")
        # logging.info(json.dumps(txinfo_estimate_req.json(), indent=2))
        txinfo_return_data = txinfo_estimate_req.json()['d']
        ret_items = txinfo_return_data['TaxLineDetails']
        ret_taxed_items = []
        if data['customer']['taxability_code']:
            txinfo_return_data['TaxJurisdictionSummary'] = "TAX: TAX EXEMPT CUSTOMER"
        if not txinfo_return_data['TaxJurisdictionSummary']: txinfo_return_data['TaxJurisdictionSummary'] = "TAX: TAX-FREE STATE"
        try:
            for ritem in ret_items:
                if data['customer']['taxability_code']:
                    ritem['SalesTaxAmount'] = 0; ritem['TaxRate'] = 0
                ret_taxed_items.append({
                    "id": ritem['ItemKey'],
                    "price": {
                        "amount_inclusive": ritem['Amount']+ritem['SalesTaxAmount'],
                        "amount_exclusive": ritem['Amount'],
                        "total_tax": ritem['SalesTaxAmount'],
                        "tax_rate": ritem['TaxRate'],
                        "sales_tax_summary": [
                            {
                                "name": txinfo_return_data['TaxJurisdictionSummary'][:200], # limit to first 200 char only
                                "rate": ritem['TaxRate'],
                                "amount": ritem['SalesTaxAmount']
                            }
                        ]
                    },
                    "type": "item"
                })
        except TypeError:
            logging.info("info from BC:")
            logging.info(json.dumps(data, indent=2))
            logging.info("info to taxinfo:")
            logging.info(json.dumps(txinfo_payload, indent=2))
            logging.info("response from taxinfo:")
            logging.info(json.dumps(txinfo_estimate_req.json(), indent=2))
            debug_log_taxes = True
        if txinfo_payload['CalculateTax']['DestinationAddress']['Region'] in ["CO","FL","IA","ID","MA","MO","OK","UT","WY"]:
            tax_rate_sh = 0
        else:
            try: tax_rate_sh = ret_items[0]['TaxRate']
            except KeyError: tax_rate_sh = 0.1
        docu_return.append({
            "id": documents['id'],
            "items": ret_taxed_items,
            "shipping": {
                "id": documents['shipping']['id'],
                "price": {
                    "amount_inclusive": assign(documents['shipping']['price'], 'amount', 0)*(1+tax_rate_sh),
                    "amount_exclusive": assign(documents['shipping']['price'], 'amount', 0),
                    "total_tax": assign(documents['shipping']['price'], 'amount', 0)*tax_rate_sh,
                    "tax_rate": tax_rate_sh,
                    "sales_tax_summary": [
                        {
                            "name": txinfo_return_data['TaxJurisdictionSummary'][:200],
                            "rate": tax_rate_sh,
                            "amount": assign(documents['shipping']['price'], 'amount', 0)*tax_rate_sh
                        }
                    ]
                },
                "type": "shipping"
            },
            "handling": {
                "id": documents['handling']['id'],
                "price": {
                    "amount_inclusive": assign(documents['handling']['price'], 'amount', 0)*(1+tax_rate_sh),
                    "amount_exclusive": assign(documents['handling']['price'], 'amount', 0),
                    "total_tax": assign(documents['handling']['price'], 'amount', 0)*tax_rate_sh,
                    "tax_rate": tax_rate_sh,
                    "sales_tax_summary": [
                        {
                            "name": txinfo_return_data['TaxJurisdictionSummary'][:200],
                            "rate": tax_rate_sh,
                            "amount": assign(documents['handling']['price'], 'amount', 0)*tax_rate_sh
                        }
                    ]
                },
                "type": "handling"
            }
        })
    # end (while documents):...
    bc_ret_payload = {
        "id": data['id'],
        "documents": docu_return
        # "sales_tax": txinfo_estimate_req.json()['d']['SalesTaxAmount']
    }
    if txinfo_estimate_req.json()['d']['SalesTaxAmount'] == 0:
        try:
            return {"error": txinfo_estimate_req.json()['d']['Errors'][0]['Message']}, 400
        except Exception:
            pass
    # logging.info("response to BC:")
    # logging.info(json.dumps(bc_ret_payload, indent=2))
    if debug_log_taxes:
        logging.info("response to BC:")
        logging.info(json.dumps(bc_ret_payload, indent=2))
    return jsonify(bc_ret_payload), 200

if debug_value: app.run() # DO NOT USE IN PRODUCTION MODE