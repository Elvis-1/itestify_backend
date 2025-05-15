from rest_framework.response import Response


class CustomResponse:
    def success(message="Success", data=None, status_code=200):
        response_data = {
            'success': True,
            'message': message,
            'data': data
        }

        response_data.pop('data', None) if data is None else ...
        return Response(data=response_data, status=status_code)
    
    def error(err_code, message="Failed", status_code=400):
        response_data = {
            'success': False,
            'message': message,
            'code': err_code
        }
               
        return Response(data=response_data, status=status_code)