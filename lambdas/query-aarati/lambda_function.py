import json

# Function to mask personal info
def mask_data(data):
    masked = {}
    
    # Mask name: only first letter visible
    if 'name' in data:
        masked['name'] = data['name'][0] + "*" * (len(data['name']) - 1)
    
    # Mask email: show only first 2 letters and domain
    if 'email' in data:
        email = data['email']
        parts = email.split("@")
        if len(parts) == 2:
            masked['email'] = parts[0][:2] + "***@" + parts[1]
        else:
            masked['email'] = "***"
    
    # Mask phone: show only last 2 digits
    if 'phone' in data:
        masked['phone'] = "***-***-" + data['phone'][-2:]
    
    return masked

def lambda_handler(event, context):
    try:
        # Convert input JSON string to Python dictionary
        body = json.loads(event['body'])
        
        masked_data = mask_data(body)
        
        # Return masked version
        return {
            'statusCode': 200,
            'body': json.dumps({
                'original': body,
                'masked': masked_data
            })
        }
    except Exception as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }
