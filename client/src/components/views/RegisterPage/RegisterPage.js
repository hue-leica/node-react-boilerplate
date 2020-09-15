import React,{useState, useRef} from 'react'
import {useDispatch} from 'react-redux';
import {registerUser} from '../../../_actions/user_action';
import {withRouter} from 'react-router-dom';

function RegisterPage(props) {
    const dispatch = useDispatch();
    const [Email, setEmail] = useState("");
    const [Password, setPassword] = useState("");
    const [Name,setName] = useState("");
    const [ConfirmPassword, setConfirmPassword] = useState("");

    const onEmailHandler = (event) =>{
        setEmail(event.currentTarget.value);
    }
    const onNamelHandler = (event) => {
        setName(event.currentTarget.value);
    }
    const onPasswordHandler = (event) => {
        setPassword(event.currentTarget.value);
    }
    const onConfirmPasswordHandler = (event) => {
        setConfirmPassword(event.currentTarget.value);
    }
    const onSubmitHandler = (event) => {
        event.preventDefault(); // 페이지 reload 막는 것

        if(Password !== ConfirmPassword){
            return alert("비밀번호와 비밀번호 확인은 같아야 합니다!");
        }
        let body = {
            email: Email,
            password: Password,
            name: Name
        }
        dispatch(registerUser(body))
        .then(response => {
            if(response.payload.success){
                props.history.push('/login');
            }else {
                alert('ERROR!');
            }
        });
    }

    return (
        <div style={{
            display: 'flex', justifyContent: 'center', alignItems: 'center',
            width: '100%', height: '100vh'
        }}>
            <form style={{ display: 'flex', flexDirection: 'column'}}
                  onSubmit={onSubmitHandler}
            >
                <label>Email</label>
                <input type="email" value={Email} onChange={onEmailHandler}/>

                <label>Name</label>
                <input type="name" value={Name} onChange={onNamelHandler}/>

                <label>Password</label>
                <input type="password" value={Password} onChange={onPasswordHandler} />

                <label>Confirm Password</label>
                <input type="password" value={ConfirmPassword} onChange={onConfirmPasswordHandler} />

                <br />
                <button type="submit"> 
                    register
                </button>
            </form>
        </div>
    )
}
export default withRouter(RegisterPage);
// props.history를 쓰기 위해 react-router-dom이 필요하다!
