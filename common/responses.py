from rest_framework.response import Response


class CustomResponse:
    def success(message="Success", data=None, status_code=200, extraFields=None):
        response_data = {
            'success': True,
            'message': message,
            'data': data,
            "extraFields": extraFields
        }

        response_data.pop('data', None) if data is None else ...
        response_data.pop('extraFields', None) if extraFields is None else ...
        return Response(data=response_data, status=status_code)
    
    def error(err_code, message="Failed", status_code=400):
        response_data = {
            'success': False,
            'message': message,
            'code': err_code
        }
               
        return Response(data=response_data, status=status_code)