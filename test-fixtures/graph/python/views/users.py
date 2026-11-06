from fastapi import APIRouter, Depends

router = APIRouter()


def get_current_user(token: str = ""):
    return token


@router.get('/users/{id}', dependencies=[Depends(get_current_user)])
def get_user(id: int):
    return {"id": id}


def run(request):
    cmd = request.GET['cmd']
    return cmd
